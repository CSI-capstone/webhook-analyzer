"""Optional real ASGI/multipart checks. Install httpx to enable this module.
Runs the shipped analysis app and a real Uvicorn sample receiver locally.
"""
import io
import json
import socket
import threading
import time
import unittest
import zipfile
from pathlib import Path

try:
    import httpx
    import uvicorn
    from fastapi.testclient import TestClient
    from app import app
    from samples.shop_server import app as shop_app
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


@unittest.skipUnless(HTTP_AVAILABLE, 'Install project dependencies and httpx for ASGI tests')
class HTTPAPITests(unittest.TestCase):
    captured = {}

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.receiver_socket = socket.socket()
        cls.receiver_socket.bind(('127.0.0.1', 0))
        cls.receiver_url = f'http://127.0.0.1:{cls.receiver_socket.getsockname()[1]}'
        cls.receiver = uvicorn.Server(uvicorn.Config(shop_app, log_level='error', lifespan='off'))
        cls.thread = threading.Thread(target=cls.receiver.run, kwargs={'sockets':[cls.receiver_socket]}, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 5
        while not cls.receiver.started and time.monotonic() < deadline:
            threading.Event().wait(.01)
        if not cls.receiver.started:
            raise RuntimeError('Sample receiver did not start')

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.receiver.should_exit = True
        cls.thread.join(timeout=5)
        cls.receiver_socket.close()

    def test_root_serves_current_frontend(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('endpoint-detail', response.text)
        self.assertIn('시연 설정', response.text)

    def test_real_multipart_source_context(self):
        response = self.client.post('/analyze', files={'code':('test.py', b"@app.post('/webhook')\nasync def hook(request):\n    return {}\n", 'text/plain')}, data={'sast_only':'true'})
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertFalse(result['dast_ran'])
        self.assertEqual(result['endpoints'][0]['sast_findings'][0]['source_context']['start_line'], 1)
        self.assertEqual(result['endpoints'][0]['sast_findings'][0]['display_path'], 'test.py')

    def test_zip_external_context_is_correct_file(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('handler.py', "from security import check\n@app.post('/webhook')\nasync def hook(request, signature=None):\n    if not check(signature, 'expected'):\n        raise ValueError('reject')\n    return {}\n")
            z.writestr('security.py', "def check(signature, expected):\n    return signature == expected\n")
        response = self.client.post('/analyze',files={'code':('project.zip', archive.getvalue(), 'application/zip')},data={'sast_only':'true'})
        self.assertEqual(response.status_code, 200)
        findings = response.json()['endpoints'][0]['sast_findings']
        external = next(f for f in findings if f['rule_id']=='WHSEC-005' and f['severity']!='INFO')
        self.assertEqual(external['display_path'], 'security.py')
        self.assertIn('signature == expected', '\n'.join(external['source_context']['lines']))

    def test_form_validation_rejects_invalid_tolerance(self):
        response = self.client.post('/analyze',files={'code':('test.py',b'pass\n','text/plain')},data={'timestamp_tolerance':'0'})
        self.assertEqual(response.status_code, 422)

    def run_shop(self, secret):
        source = Path(__file__).parents[1]/'samples/shop_server.py'
        response = self.client.post('/analyze',files={'code':('shop_server.py',source.read_bytes(),'text/plain')},data={'webhook_url':self.receiver_url,'secret':secret,'state_create':'/orders','state_query':'/orders/{id}','timestamp_tolerance':'300'})
        self.assertEqual(response.status_code,200)
        return response.json()

    def test_dynamic_shop_has_actual_processing_evidence(self):
        result = self.run_shop('dku-toss-secret-2026')
        endpoint = result['endpoints'][0]
        self.assertTrue(endpoint['probe']['baseline_valid'])
        self.assertTrue(any(a['status']=='vulnerable' and a['state_changed'] for a in endpoint['dast_results'] if a['attack_type']=='replay'))
        self.assertTrue(all('source_context' in f for f in endpoint['sast_findings']))
        type(self).captured['shop'] = result

    def test_wrong_secret_is_inconclusive(self):
        result = self.run_shop('incorrect-test-key')
        endpoint = result['endpoints'][0]
        self.assertFalse(endpoint['probe']['baseline_valid'])
        self.assertTrue(all(a['status']=='inconclusive' for a in endpoint['dast_results']))
        type(self).captured['wrong-key'] = result


if __name__ == '__main__':
    unittest.main(verbosity=2)
