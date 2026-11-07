"""/analyze 함수의 업로드·분석·리포트 연결 단위 시험.
FastAPI가 없는 환경에서는 선언 인터페이스만 대역으로 제공한다.
HTTP 라우팅/ASGI/브라우저 검증을 대체하지 않는다.
"""
import asyncio
import importlib.util
import io
import json
import runpy
import sys
import threading
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from http.server import HTTPServer
from server.test_server import Handler
from analyzer.dast import DASTEngine


class Response:
    def __init__(self, content, status_code=200):
        self.body=json.dumps(content).encode() if not isinstance(content,str) else content.encode()
        self.status_code=status_code


class HTTPError(Exception):
    def __init__(self,status_code,detail):
        self.status_code=status_code;self.detail=detail


def load_pipeline():
    path=str(Path(__file__).parents[1]/'app.py')
    if importlib.util.find_spec('fastapi') is not None:
        return runpy.run_path(path)
    fake=types.ModuleType('fastapi');responses=types.ModuleType('fastapi.responses')
    class App:
        def __init__(self,**kwargs): pass
        def get(self,*args,**kwargs): return lambda function:function
        post=get
    fake.FastAPI=App;fake.File=lambda *a,**kw:None;fake.Form=lambda *a,**kw:None
    fake.HTTPException=HTTPError;fake.UploadFile=object
    responses.JSONResponse=Response;responses.HTMLResponse=Response
    with patch.dict(sys.modules,{'fastapi':fake,'fastapi.responses':responses}):
        return runpy.run_path(path)


class Upload:
    def __init__(self,data,name): self.data=data;self.filename=name
    async def read(self,size=-1): return self.data if size < 0 else self.data[:size]


class APIPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.module=load_pipeline()

    def analyze(self,data,name='test.py',**kwargs):
        options=dict(code=Upload(data,name),webhook_url='',state_create='',state_query='',secret='',sast_only=False,strict_json=False,timestamp_tolerance=300)
        options.update(kwargs)
        response=asyncio.run(self.module['analyze'](**options))
        return json.loads(response.body)

    @staticmethod
    def archive(entries):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as z:
            for name,value in entries.items(): z.writestr(name,value)
        return output.getvalue()

    def test_empty_url_runs_sast_only(self):
        result=self.analyze(b"@app.post('/webhook')\nasync def hook(request):\n    return {}\n")
        self.assertFalse(result['dast_ran'])
        self.assertEqual(result['total_sast_findings'],1)

    def test_source_context_matches_uploaded_file(self):
        text=b"@app.post('/webhook')\nasync def hook(request):\n    return {}\n"
        result=self.analyze(text)
        finding=result['endpoints'][0]['sast_findings'][0]
        self.assertEqual(finding['display_path'], 'test.py')
        self.assertEqual(finding['source_context']['start_line'], 1)
        self.assertEqual(finding['source_context']['lines'], text.decode().splitlines())

    def test_source_context_does_not_read_outside_upload(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            endpoints=[{'sast_findings':[{'filepath':__file__, 'lineno':1}]}]
            self.module['_attach_source_context'](endpoints, root)
        self.assertNotIn('source_context', endpoints[0]['sast_findings'][0])

    def test_external_finding_survives_sast_only(self):
        payload=self.archive({'wrapper/handler.py':"from security import check\n@app.post('/webhook')\nasync def hook(request, signature=None):\n    if not check(signature,'expected'):\n        raise ValueError('reject')\n    return {}\n",'wrapper/security.py':"def check(signature,expected):\n    return signature == expected\n"})
        result=self.analyze(payload,'test.zip')
        findings=result['endpoints'][0]['sast_findings']
        self.assertTrue(any(f['rule_id']=='WHSEC-005' and f['severity']!='INFO' for f in findings))

    def test_same_function_names_keep_their_own_findings(self):
        payload=self.archive({'one.py':"@app.post('/webhook/one')\nasync def hook(request):\n    return {}\n",'two.py':"import hmac\n@app.post('/webhook/two')\nasync def hook(request,signature=None):\n    if not hmac.compare_digest(signature,'expected'):\n        raise ValueError('reject')\n    return {}\n"})
        result=self.analyze(payload,'test.zip')
        by_path={e['path']:e for e in result['endpoints']}
        self.assertTrue(any(f['rule_id']=='WHSEC-001' for f in by_path['/webhook/one']['sast_findings']))
        self.assertEqual(by_path['/webhook/two']['sast_findings'],[])

    def test_parse_error_is_visible_and_prevents_grade_a(self):
        payload=self.archive({'good.py':"import hmac\n@app.post('/webhook')\nasync def hook(request,signature=None):\n    if not hmac.compare_digest(signature,'expected'):\n        raise ValueError('reject')\n    return {}\n",'bad.py':'def broken('})
        result=self.analyze(payload,'test.zip')
        self.assertTrue(result['analysis_warnings'])
        self.assertTrue(result['overall_grade'].startswith('N/A'))

    def test_undecodable_source_is_reported(self):
        payload=self.archive({'good.py':"@app.post('/webhook')\nasync def hook(request):\n    return {}\n",'bad.py':b'\xff\xfe\xfa'})
        result=self.analyze(payload,'test.zip')
        self.assertTrue(result['analysis_warnings'])
        self.assertEqual(result['analysis_status'],'partial')

    def test_duplicate_routes_do_not_use_one_guessed_platform(self):
        text=b"@app.post('/webhook')\nasync def a(request,stripe_signature=None):\n    return {}\n@app.post('/webhook')\nasync def b(request,x_slack_signature=None):\n    return {}\n"
        result=self.analyze(text,webhook_url='http://127.0.0.1:0',secret='test')
        self.assertTrue(result['analysis_warnings'])
        self.assertTrue(all(a['status']=='inconclusive' for a in result['endpoints'][0]['dast_results']))

    def test_non_http_url_rejected(self):
        with self.assertRaises(Exception) as caught:
            self.analyze(b"@app.post('/webhook')\nasync def hook(request):\n    return {}\n",webhook_url='file:///tmp')
        self.assertEqual(caught.exception.status_code,422)

    def test_mixed_platforms_use_their_own_headers(self):
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        text="@app.post('/webhook/stripe')\nasync def a(request,stripe_signature=None):\n    return {}\n@app.post('/webhook/slack')\nasync def b(request,x_slack_signature=None):\n    return {}\n"
        def fast_engine(config):
            config.request_interval=0;config.state_check_delay=0;config.max_retries=0
            return DASTEngine(config)
        try:
            with patch.dict(self.module['analyze'].__globals__,{'DASTEngine':fast_engine}):
                result=self.analyze(text.encode(),webhook_url=f'http://127.0.0.1:{server.server_port}',secret='supersecretkey',state_create='/orders',state_query='/orders/{id}')
            self.assertEqual([e['platform']['platform'] for e in result['endpoints']],['Stripe','Slack'])
            self.assertTrue(all(e['probe']['baseline_valid'] for e in result['endpoints']))
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_unfilled_path_parameter_is_not_requested(self):
        text=b"@app.post('/webhook/{shop_id}')\nasync def hook(request):\n    return {}\n"
        result=self.analyze(text,webhook_url='http://127.0.0.1:0',secret='test')
        endpoint=result['endpoints'][0]
        self.assertTrue(endpoint['probe']['validation_error'])
        self.assertTrue(all(a['status']=='inconclusive' for a in endpoint['dast_results']))


if __name__=='__main__': unittest.main()
