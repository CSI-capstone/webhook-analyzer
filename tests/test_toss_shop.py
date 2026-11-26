"""토스 서명 형식으로 바꾼 쇼핑몰의 요청 처리와 일반 HMAC 예제 보존 검사."""
import ast
import base64
import hashlib
import hmac
import json
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from analyzer.engine import WebhookASTEngine
from analyzer.platform import PlatformDetector, Platform
from analyzer.sast import SASTEngine
from samples import generic_shop_server, shop_server


def signed_headers(body, transmission_time, key=shop_server.WEBHOOK_SECRET):
    digest = hmac.new(key, body + b":" + transmission_time.encode(), hashlib.sha256).digest()
    return {"Content-Type": "application/json", "TossPayments-Webhook-Transmission-Time": transmission_time,
            "TossPayments-Webhook-Signature": "v1:" + base64.b64encode(digest).decode()}


class TossShopTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(shop_server.app)
        self.addCleanup(self.client.close)
        self.order_id = self.client.post("/orders", json={"product_id": "P001"}).json()["order_id"]
        self.body = json.dumps({"eventType": "PAYMENT_STATUS_CHANGED", "data": {
            "orderId": self.order_id, "paymentKey": "demo_key", "status": "DONE"}}).encode()
        self.sent_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def state(self):
        return self.client.get(f"/orders/{self.order_id}").json()["status"]

    def test_toss_signature_accepts_payment_and_shop_ui_remains(self):
        response = self.client.post("/webhook/toss-payment", content=self.body,
                                    headers=signed_headers(self.body, self.sent_at))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.state(), "paid")
        self.assertIn("토스페이먼츠 서명 형식", self.client.get("/").text)
        self.assertEqual(self.client.get("/products").status_code, 200)

    def test_multiple_signatures_accept_a_valid_entry_in_either_position(self):
        valid = signed_headers(self.body, self.sent_at)["TossPayments-Webhook-Signature"]
        wrong = signed_headers(self.body, self.sent_at, b"wrong-key")["TossPayments-Webhook-Signature"]
        for combined in (wrong + "," + valid, valid + "," + wrong, "v2:ignored,v1:not!base64," + valid):
            with self.subTest(header=combined):
                headers = signed_headers(self.body, self.sent_at)
                headers["TossPayments-Webhook-Signature"] = combined
                self.assertEqual(self.client.post("/webhook/toss-payment", content=self.body, headers=headers).status_code, 200)

    def test_missing_invalid_old_generic_and_tampered_requests_are_rejected(self):
        for variant in ("missing_signature", "missing_time", "wrong_key", "body_tamper", "time_tamper", "bad_base64", "old_generic"):
            with self.subTest(variant=variant):
                body = self.body
                headers = signed_headers(body, self.sent_at, b"wrong-key" if variant == "wrong_key" else shop_server.WEBHOOK_SECRET)
                if variant == "missing_signature":
                    headers.pop("TossPayments-Webhook-Signature")
                elif variant == "missing_time":
                    headers.pop("TossPayments-Webhook-Transmission-Time")
                elif variant == "body_tamper":
                    body += b" "
                elif variant == "time_tamper":
                    headers["TossPayments-Webhook-Transmission-Time"] = "2000-01-01T00:00:00+00:00"
                elif variant == "bad_base64":
                    headers["TossPayments-Webhook-Signature"] = "v1:not!base64"
                elif variant == "old_generic":
                    headers = {"Content-Type": "application/json", "X-Signature": "sha256=" + hmac.new(shop_server.WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()}
                response = self.client.post("/webhook/toss-payment", content=body, headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(self.state(), "pending")

    def test_expired_but_valid_signature_preserves_intentional_demo_flaw(self):
        old = datetime.fromtimestamp(time.time() - 360, timezone.utc).isoformat(timespec="seconds")
        response = self.client.post("/webhook/toss-payment", content=self.body, headers=signed_headers(self.body, old))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.state(), "paid")

    def test_wrong_input_formats_are_rejected_without_state_change(self):
        for variant in ("content_type", "array", "wrong_event"):
            with self.subTest(variant=variant):
                body = b"[" + self.body + b"]" if variant == "array" else self.body
                if variant == "wrong_event":
                    body = body.replace(b"PAYMENT_STATUS_CHANGED", b"payout.changed")
                headers = signed_headers(body, self.sent_at)
                if variant == "content_type":
                    headers["Content-Type"] = "text/plain"
                response = self.client.post("/webhook/toss-payment", content=body, headers=headers)
                self.assertEqual(response.status_code, 415 if variant == "content_type" else 400)
                self.assertEqual(self.state(), "pending")

    def test_sast_platform_and_iso_time_fix_match_the_example(self):
        pr = WebhookASTEngine().parse_file(str(Path(shop_server.__file__)))
        results = SASTEngine().analyze(pr)
        self.assertEqual(sorted(f.rule_id for f in results), ["WHSEC-002", "WHSEC-004"])
        detection = PlatformDetector().detect_per_handler(pr)["toss_payment_webhook"]
        self.assertEqual(detection.platform, Platform.TOSS_PAYMENTS)
        fix = next(f.fix_snippet for f in results if f.rule_id == "WHSEC-004")
        ast.parse(fix)
        self.assertIn("datetime.fromisoformat", fix)
        # 적용 예제가 ISO 8601 전송 시각을 실제로 해석해 정상/만료를 구분하는지 검사한다.
        from fastapi import HTTPException
        namespace = {"tosspayments_webhook_transmission_time": self.sent_at, "HTTPException": HTTPException}
        exec(compile(fix, "<generated-time-fix>", "exec"), namespace)
        namespace["tosspayments_webhook_transmission_time"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(HTTPException):
            exec(compile(fix, "<generated-time-fix>", "exec"), namespace)

    def test_generic_example_still_accepts_its_original_signature(self):
        with TestClient(generic_shop_server.app) as client:
            order_id = client.post("/orders", json={"product_id": "P001"}).json()["order_id"]
            body = json.dumps({"order_id": order_id}).encode()
            headers = {"Content-Type": "application/json", "X-Timestamp": str(int(time.time())),
                       "X-Signature": "sha256=" + hmac.new(generic_shop_server.WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()}
            self.assertEqual(client.post("/webhook/generic-payment", content=body, headers=headers).status_code, 200)
            self.assertEqual(client.get(f"/orders/{order_id}").json()["status"], "paid")
        pr = WebhookASTEngine().parse_file(str(Path(generic_shop_server.__file__)))
        detection = PlatformDetector().detect_per_handler(pr)["generic_payment_webhook"]
        self.assertEqual(detection.platform, Platform.GENERIC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
