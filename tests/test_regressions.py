"""판정 오류를 재현하는 회귀 테스트. python -m unittest discover -s tests -v"""
import ast
import base64
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from analyzer.engine import WebhookASTEngine
from analyzer.sast import SASTEngine, Finding, Severity
from analyzer.dast import DASTEngine, DastConfig, Tier, Verdict, AttackType, AttackResult, Confidence, _generate_mock_payload
from analyzer.platform import PlatformDetector, Platform
from analyzer.report import compute_endpoint_report, compute_full_report, group_findings
from analyzer.serializer import full_report_to_dict
from backend.upload import process_upload, cleanup, UploadError
from server.test_server import Handler, _order_db, _db_lock
from http.server import HTTPServer


def findings(source, filepath='<string>'):
    return SASTEngine().analyze(WebhookASTEngine().parse_source(source, filepath))


def source(body, params='request, signature=None, x_timestamp=None', imports='import hmac,hashlib,time'):
    return imports + "\n@app.post('/webhook/test')\nasync def hook(" + params + "):\n" + '\n'.join('    ' + line for line in body.splitlines()) + '\n'


class StaticRegressions(unittest.TestCase):
    def has_rule(self, text, rule):
        return any(f.rule_id == rule and f.severity != Severity.INFO for f in findings(text))

    def test_computing_mac_is_not_verification(self):
        text=source("payload=await request.body()\nunused=hmac.new(b'key',payload,hashlib.sha256).hexdigest()\nreturn {'processed':True}")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_fake_verify_function(self):
        text="def verify_signature(*args):\n    return True\n" + source("if not verify_signature(signature):\n    raise ValueError('reject')\nreturn {'processed':True}")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_ignored_compare_result(self):
        self.assertTrue(self.has_rule(source("hmac.compare_digest(signature,'expected')\nreturn {'processed':True}"),'WHSEC-001'))

    def test_logging_clock_does_not_validate_timestamp(self):
        text=source("print(time.time())\nif not hmac.compare_digest(signature,'expected'):\n    raise ValueError('reject')\nreturn {'processed':True}")
        self.assertTrue(self.has_rule(text,'WHSEC-004'))

    def test_fake_timestamp_function(self):
        text="def verify_timestamp(ts):\n    return True\n" + source("if not hmac.compare_digest(signature,'expected'):\n    raise ValueError('reject')\nif not verify_timestamp(x_timestamp):\n    raise ValueError('reject')\nreturn {'processed':True}")
        self.assertTrue(self.has_rule(text,'WHSEC-004'))

    def test_hmac_alias_and_keyword_digestmod(self):
        text=source("expected=hm.new(b'key',b'body',digestmod=weak).hexdigest()\nif not hm.compare_digest(signature,expected):\n    raise ValueError('reject')\nreturn {'processed':True}",imports='import hmac as hm\nfrom hashlib import md5 as weak')
        self.assertTrue(self.has_rule(text,'WHSEC-003'))
        self.assertFalse(self.has_rule(text,'WHSEC-001'))

    def test_string_digest_algorithm(self):
        self.assertTrue(self.has_rule(source("expected=hmac.new(b'key',b'body',digestmod='md5').hexdigest()\nif not hmac.compare_digest(signature,expected):\n    raise ValueError('reject')\nreturn {}"),'WHSEC-003'))

    def test_not_equal_fix_keeps_rejection_polarity(self):
        fs=findings(source("expected='computed'\nif signature != expected:\n    raise ValueError('reject')\nreturn {}"))
        fix=next(f.fix_snippet for f in fs if f.rule_id=='WHSEC-002')
        self.assertIn('if not hmac.compare_digest(signature, expected):',fix)
        ast.parse(fix)

    def test_signature_guard_wrong_polarity_is_not_trusted(self):
        text=source("if hmac.compare_digest(signature,'expected'):\n    raise ValueError('reject')\nreturn {}")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_positive_or_bypass_is_not_trusted(self):
        text=source("if bypass or hmac.compare_digest(signature,'expected'):\n    return {}\nraise ValueError('reject')")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_dead_negative_guard_is_not_trusted(self):
        text=source("if not hmac.compare_digest(signature,'expected') and False:\n    raise ValueError('reject')\nreturn {}")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_none_check_is_not_timing_compare(self):
        self.assertFalse(self.has_rule(source("if signature == None:\n    raise ValueError('missing')\nreturn {}"),'WHSEC-002'))

    def test_unresolved_verifier_is_incomplete(self):
        fs=findings(source("if not custom_verify(signature):\n    raise ValueError('reject')\nreturn {}"))
        self.assertTrue(any(f.rule_id=='WHSEC-001' and f.severity==Severity.INFO for f in fs))
        report=compute_full_report('test',[compute_endpoint_report('/webhook/test',Tier.TIER_2,fs,[])])
        self.assertTrue(report.overall_grade.startswith('N/A'))

    def test_source_is_never_executed(self):
        text="raise RuntimeError('must not execute')\n"+source("return {}")
        self.assertTrue(self.has_rule(text,'WHSEC-001'))

    def test_external_module_alias_and_finding_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'security.py').write_text('import hmac\ndef check(signature,expected):\n    return signature == expected\n')
            handler=root/'handler.py'
            handler.write_text(source("if not sec.check(signature,'expected'):\n    raise ValueError('reject')\nreturn {}",imports='import security as sec'))
            pr=WebhookASTEngine().parse_file(str(handler),str(root))
            fs=SASTEngine().analyze(pr)
            external=next(f for f in fs if f.rule_id=='WHSEC-005' and f.severity!=Severity.INFO)
            self.assertEqual(external.origin_filepath,str(handler))
            self.assertEqual(Path(external.filepath).name,'security.py')
            self.assertIn(external,group_findings([pr],fs)['/webhook/test'])

    def test_relative_import_under_zip_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            package=Path(directory)/'outer'/'app';package.mkdir(parents=True)
            (package/'security.py').write_text('def check(signature,expected):\n    return signature == expected\n')
            handler=package/'handler.py';handler.write_text(source("if not check(signature,'expected'):\n    raise ValueError('reject')\nreturn {}",imports='from .security import check'))
            pr=WebhookASTEngine().parse_file(str(handler),directory)
            self.assertTrue(any(f.rule_id=='WHSEC-005' and f.severity!=Severity.INFO for f in SASTEngine().analyze(pr)))

    def test_keyword_only_header_alias(self):
        text=source('return {}',params="request, *, signature=Header(None,alias='Stripe-Signature')")
        pr=WebhookASTEngine().parse_source(text)
        self.assertEqual(pr.routes[0].header_params[0].header_name,'Stripe-Signature')

    def test_flask_get_post_route_selects_post(self):
        text="@app.route('/webhook',methods=['GET','POST'])\ndef hook():\n    return {}\n"
        self.assertEqual(WebhookASTEngine().parse_source(text).routes[0].method,'POST')

    def test_direct_header_read_identifies_non_keyword_route(self):
        text=source("signature=request.headers.get('Stripe-Signature')\nreturn {}",params='request').replace('/webhook/test','/api/payment')
        pr=WebhookASTEngine().parse_source(text)
        self.assertEqual(len(pr.handlers),1)
        detection=PlatformDetector().detect_per_handler(pr)['hook']
        self.assertEqual(detection.platform,Platform.STRIPE)

    def test_multiple_platforms_are_independent(self):
        text=source('return {}',params='request, stripe_signature=None').replace('hook(', 'stripe_hook(')
        text+=source('return {}',params='request, x_slack_signature=None').replace('hook(', 'slack_hook(').replace('/webhook/test','/webhook/slack')
        detections=PlatformDetector().detect_per_handler(WebhookASTEngine().parse_source(text))
        self.assertEqual(detections['stripe_hook'].platform,Platform.STRIPE)
        self.assertEqual(detections['slack_hook'].platform,Platform.SLACK)


class ScenarioHandler(Handler):
    def do_POST(self):
        special={'/always500':500,'/ack':202,'/redirect':302,'/rate':429,'/reject-all':401}
        if self.path in special:
            self._body();self._json(special[self.path],{'ignored':True});return
        super().do_POST()


class DynamicRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=HTTPServer(('127.0.0.1',0),ScenarioHandler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=2)

    def setUp(self):
        with _db_lock: _order_db.clear()
        self.clients=[]

    def tearDown(self):
        for client in self.clients: client.close()

    def engine(self,**overrides):
        values=dict(base_url=self.url,secret=b'supersecretkey',sig_header='X-Signature',request_interval=0,state_check_delay=0,max_retries=0,timeout=.5)
        values.update(overrides)
        client=DASTEngine(DastConfig(**values));self.clients.append(client);return client

    def test_probe_records_401_response(self):
        engine=self.engine();probe=engine.probe('/webhook/secure')
        self.assertEqual(probe.step1_code,401);self.assertEqual(probe.step2_code,401)
        self.assertTrue(probe.baseline_valid)

    def test_500_is_inconclusive(self):
        engine=self.engine();probe=engine.probe('/always500')
        self.assertEqual(probe.step3_code,500)
        self.assertTrue(all(a.status==Verdict.INCONCLUSIVE for a in engine.run_all('/always500',probe)))

    def test_wrong_secret_is_not_safe(self):
        engine=self.engine(secret=b'wrong');probe=engine.probe('/webhook/no-timestamp')
        self.assertFalse(probe.baseline_valid)
        self.assertTrue(all(a.status==Verdict.INCONCLUSIVE for a in engine.run_all('/webhook/no-timestamp',probe)))

    def test_no_secret_is_skipped(self):
        engine=self.engine(secret=b'');probe=engine.probe('/webhook/no-timestamp')
        self.assertTrue(all(a.status==Verdict.SKIPPED for a in engine.run_all('/webhook/no-timestamp',probe)))

    def test_ack_without_processing_is_only_observation(self):
        engine=self.engine();probe=engine.probe('/ack');attacks=engine.run_all('/ack',probe)
        self.assertTrue(probe.baseline_valid)
        self.assertTrue(all(a.status==Verdict.OBSERVED for a in attacks))
        report=compute_full_report('ack',[compute_endpoint_report('/ack',probe.tier,[],attacks)])
        self.assertTrue(report.overall_grade.startswith('N/A'))

    def test_redirect_is_not_followed(self):
        engine=self.engine();probe=engine.probe('/redirect')
        self.assertEqual(probe.step3_code,302)
        self.assertTrue(all(a.status==Verdict.INCONCLUSIVE for a in engine.run_all('/redirect',probe)))

    def test_rate_limit_is_not_rejection_evidence(self):
        engine=self.engine();probe=engine.probe('/rate')
        self.assertTrue(all(a.status==Verdict.INCONCLUSIVE for a in engine.run_all('/rate',probe)))

    def test_type_acceptance_needs_declared_policy(self):
        engine=self.engine();probe=engine.probe('/webhook/no-timestamp')
        attacks=engine.attack_type_confusion('/webhook/no-timestamp',probe)
        self.assertTrue(all(a.state_changed for a in attacks))
        self.assertTrue(all(a.status==Verdict.OBSERVED for a in attacks))
        engine.cfg.strict_json=True
        self.assertTrue(all(a.status==Verdict.VULNERABLE for a in engine.attack_type_confusion('/webhook/no-timestamp',probe)))

    def test_tier2_acceptance_is_not_confirmed(self):
        engine=self.engine(state_create_path='',state_query_template='')
        probe=engine.probe('/webhook/no-verify')
        self.assertEqual(probe.tier,Tier.TIER_2)
        self.assertTrue(all(not a.vulnerable for a in engine.run_all('/webhook/no-verify',probe)))

    def test_state_query_error_is_not_change(self):
        engine=self.engine();probe=engine.probe('/webhook/no-timestamp')
        with patch.object(engine,'_query_state',side_effect=['pending',None,'pending',None]):
            results=engine.attack_replay('/webhook/no-timestamp',probe)
        self.assertTrue(all(not a.state_changed and not a.vulnerable for a in results))

    def test_expired_body_and_refreshed_header_are_rejected(self):
        engine=self.engine();probe=engine.probe('/webhook/secure')
        results=engine.attack_replay('/webhook/secure',probe)
        self.assertEqual({a.variant for a in results},{'expired_timestamp','timestamp_header_refresh'})
        self.assertTrue(all(a.status==Verdict.REJECTED for a in results))

    def test_declared_tolerance_changes_replay_age(self):
        engine=self.engine(timestamp_tolerance=600);probe=engine.probe('/webhook/secure')
        self.assertTrue(all(a.status==Verdict.REJECTED for a in engine.attack_replay('/webhook/secure',probe)))

    def test_connection_error_is_inconclusive(self):
        engine=self.engine(base_url='http://127.0.0.1:0',timeout=.1)
        probe=engine.probe('/webhook/secure')
        self.assertTrue(probe.connection_error)
        self.assertTrue(all(a.status==Verdict.INCONCLUSIVE for a in engine.run_all('/webhook/secure',probe)))


class SignatureVectors(unittest.TestCase):
    def test_known_wire_formats(self):
        body=b'{"hello":"world"}';ts='1700000000'
        vectors={
            'generic':'sha256=84cc33df716ed0b0598f07437c94069ace3730358778a592bd6bbd1423d111f3',
            'github':'sha256=84cc33df716ed0b0598f07437c94069ace3730358778a592bd6bbd1423d111f3',
            'stripe':'t=1700000000,v1=f85455a1b55ea86f7a15f5f9923d0abc4b888da84ec485f2ff358f427776beca',
            'slack':'v0=8429be9e0d7bdcafb444236fd24e321fcf4ec3f1d460db5a392366a784b25574',
            'toss':'v1:BKH5wsKpv/rHTvo8SX6Hjs+4eH7rspWvtAbnhL8PM9A=',
            'portone':'v1,Lou7lPyhB1WtwjmqwXJWMFfedA4HQ/JhXUMAc3Bw0Hg=',
        }
        for platform,expected in vectors.items():
            with self.subTest(platform=platform):
                key=b'whsec_'+base64.b64encode(b'test-secret') if platform=='portone' else b'test-secret'
                engine=DASTEngine(DastConfig(base_url='http://127.0.0.1',platform_name=platform,secret=key))
                try: self.assertEqual(engine._make_signature(key,body,ts,message_id='evt_test'),expected)
                finally: engine.close()

    def test_toss_payload_is_signed_event_family(self):
        value=json.loads(_generate_mock_payload('toss','order1',1700000000))
        self.assertEqual(value['eventType'],'payout.changed')
        self.assertIn('entityBody',value)
        self.assertTrue(value['createdAt'].endswith('+00:00'))


class ReportRegressions(unittest.TestCase):
    def attack(self,kind=AttackType.REPLAY,related=None,status=Verdict.VULNERABLE):
        return AttackResult(kind,'/webhook',Tier.TIER_1,True,Confidence.HIGH,'test',status=status,related_rule_ids=related or ['WHSEC-004'])

    def test_dynamic_only_is_not_grade_a(self):
        er=compute_endpoint_report('/webhook',Tier.TIER_1,[],[self.attack()])
        report=compute_full_report('test',[er])
        self.assertEqual(er.overall_severity,Severity.MEDIUM)
        self.assertFalse(report.overall_grade.startswith('A'))
        self.assertEqual(full_report_to_dict(report)['total_dast_vulns'],1)

    def test_different_weaknesses_do_not_cross_confirm(self):
        finding=Finding('WHSEC-002','timing',Severity.HIGH,'test','x.py','hook',1,cvss_score=7.4)
        er=compute_endpoint_report('/webhook',Tier.TIER_1,[finding],[self.attack()])
        self.assertIn('같은 결함의 교차 확인은 아님',er.combined_note)
        self.assertEqual(er.overall_cvss,7.4)

    def test_same_weakness_does_not_add_cvss(self):
        finding=Finding('WHSEC-004','time',Severity.MEDIUM,'test','x.py','hook',1,cvss_score=5.9)
        er=compute_endpoint_report('/webhook',Tier.TIER_1,[finding],[self.attack()])
        self.assertIn('WHSEC-004',er.combined_note)
        self.assertEqual(er.overall_cvss,5.9)

    def test_info_is_not_vulnerability_or_clean_bill(self):
        finding=Finding('WHSEC-005','unknown',Severity.INFO,'test','x.py','hook',1)
        report=compute_full_report('test',[compute_endpoint_report('/webhook',Tier.TIER_2,[finding],[])])
        self.assertEqual(report.total_sast_findings,0)
        self.assertTrue(report.overall_grade.startswith('N/A'))

    def test_no_endpoints_is_not_grade_a(self):
        self.assertTrue(compute_full_report('test',[]).overall_grade.startswith('N/A'))


class UploadRegressions(unittest.TestCase):
    def archive(self,entries):
        data=io.BytesIO()
        with zipfile.ZipFile(data,'w') as output:
            for name,value in entries: output.writestr(name,value)
        return data.getvalue()

    def test_absolute_parent_and_windows_paths_are_not_extracted(self):
        payload=self.archive([('/tmp/forbidden.py','bad'),('../forbidden.py','bad'),('C:/forbidden.py','bad'),('ok.py','x=1')])
        directory,files=process_upload(payload,'test.zip')
        try:
            self.assertEqual([Path(f).name for f in files],['ok.py'])
            self.assertTrue(all(Path(f).is_relative_to(Path(directory)) for f in files))
        finally: cleanup(directory)

    def test_too_many_entries_are_rejected(self):
        with self.assertRaises(UploadError):
            process_upload(self.archive([(f'{i}.py','') for i in range(2001)]),'test.zip')


if __name__=='__main__': unittest.main()
