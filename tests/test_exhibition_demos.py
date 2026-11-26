"""추가 시연 서버의 실제 요청 처리 및 HookLens 업로드 분석 검사.

프로젝트 의존성과 httpx 설치 후:
python -m unittest tests.test_exhibition_demos -v
"""
import hashlib
import hmac
import json
import socket
import threading
import time
import unittest
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient

from app import app as analyzer_app
from samples import slack_demo_server, stripe_demo_server

CASES = (
    ("stripe", stripe_demo_server, "paid", 1),
    ("slack", slack_demo_server, "processed", 2),
)


def signed_headers(platform, payload, timestamp, secret):
    if platform == "stripe":
        message = f"{timestamp}.".encode() + payload
        digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
        return {"Content-Type": "application/json", "Stripe-Signature": f"t={timestamp},v1={digest}"}
    message = f"v0:{timestamp}:".encode() + payload
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "X-Slack-Signature": f"v0={digest}",
            "X-Slack-Request-Timestamp": str(timestamp)}


class ExhibitionDemoTests(unittest.TestCase):
    def test_normal_signatures_work_on_both_paths(self):
        for platform, module, final_state, _ in CASES:
            with TestClient(module.app) as client:
                for suffix in ("", "-fixed"):
                    with self.subTest(platform=platform, path=suffix or "vulnerable"):
                        order_id = client.post("/orders", json={"item": "analyzer_test"}).json()["order_id"]
                        body = json.dumps({"order_id": order_id}).encode()
                        headers = signed_headers(platform, body, int(time.time()), module.WEBHOOK_SECRET)
                        response = client.post(f"/webhook/{platform}{suffix}", content=body, headers=headers)
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(client.get(f"/orders/{order_id}").json()["status"], final_state)

    def test_missing_and_tampered_requests_are_rejected_without_state_change(self):
        for platform, module, _, _ in CASES:
            with TestClient(module.app) as client:
                for suffix in ("", "-fixed"):
                    for variant in ("missing", "wrong_key", "body_tamper"):
                        with self.subTest(platform=platform, path=suffix, variant=variant):
                            order_id = client.post("/orders").json()["order_id"]
                            body = json.dumps({"order_id": order_id}).encode()
                            key = b"wrong-key" if variant == "wrong_key" else module.WEBHOOK_SECRET
                            headers = signed_headers(platform, body, int(time.time()), key)
                            if variant == "missing":
                                headers.pop("Stripe-Signature" if platform == "stripe" else "X-Slack-Signature")
                            if variant == "body_tamper":
                                body = body[:-1] + b', "tampered": true}'
                            response = client.post(f"/webhook/{platform}{suffix}", content=body, headers=headers)
                            self.assertEqual(response.status_code, 401)
                            self.assertEqual(client.get(f"/orders/{order_id}").json()["status"], "pending")

    def test_expired_and_future_requests_distinguish_fixed_paths(self):
        for platform, module, final_state, _ in CASES:
            with TestClient(module.app) as client:
                for suffix in ("", "-fixed"):
                    for offset in (-360, 360):
                        with self.subTest(platform=platform, path=suffix, offset=offset):
                            order_id = client.post("/orders").json()["order_id"]
                            body = json.dumps({"order_id": order_id}).encode()
                            headers = signed_headers(platform, body, int(time.time()) + offset, module.WEBHOOK_SECRET)
                            response = client.post(f"/webhook/{platform}{suffix}", content=body, headers=headers)
                            self.assertEqual(response.status_code, 401 if suffix else 200)
                            self.assertEqual(client.get(f"/orders/{order_id}").json()["status"],
                                             "pending" if suffix else final_state)

    def test_slack_time_header_cannot_be_refreshed_without_resigning(self):
        module = slack_demo_server
        with TestClient(module.app) as client:
            for suffix in ("", "-fixed"):
                order_id = client.post("/orders").json()["order_id"]
                body = json.dumps({"order_id": order_id}).encode()
                headers = signed_headers("slack", body, int(time.time()) - 360, module.WEBHOOK_SECRET)
                headers["X-Slack-Request-Timestamp"] = str(int(time.time()))
                response = client.post(f"/webhook/slack{suffix}", content=body, headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(client.get(f"/orders/{order_id}").json()["status"], "pending")

    def test_real_receiver_and_uploaded_sources_match_analysis_results(self):
        """실제 Uvicorn 수신 서버와 multipart 분석 요청을 함께 검사한다."""
        for platform, module, _, sast_count in CASES:
            with self.subTest(platform=platform):
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                base_url = f"http://127.0.0.1:{sock.getsockname()[1]}"
                server = uvicorn.Server(uvicorn.Config(module.app, log_level="error", lifespan="off"))
                thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 5
                    while not server.started and time.monotonic() < deadline:
                        threading.Event().wait(0.01)
                    self.assertTrue(server.started, "시연 수신 서버 시작 실패")
                    source = Path(module.__file__)
                    with TestClient(analyzer_app) as client:
                        response = client.post("/analyze",
                            files={"code": (source.name, source.read_bytes(), "text/plain")},
                            data={"webhook_url": base_url, "secret": module.WEBHOOK_SECRET.decode(),
                                  "state_create": "/orders", "state_query": "/orders/{id}",
                                  "timestamp_tolerance": "300"})
                    self.assertEqual(response.status_code, 200, response.text)
                    result = response.json()
                    endpoints = {endpoint["path"]: endpoint for endpoint in result["endpoints"]}
                    vulnerable = endpoints[f"/webhook/{platform}"]
                    fixed = endpoints[f"/webhook/{platform}-fixed"]
                    self.assertEqual(result["total_sast_findings"], sast_count)
                    self.assertEqual(result["total_dast_vulns"], 1)
                    self.assertEqual(result["analysis_status"], "complete")
                    self.assertTrue(all(e["probe"]["baseline_valid"] for e in endpoints.values()))
                    self.assertTrue(all(e["tier"] == "Tier 1" for e in endpoints.values()))
                    self.assertTrue(all(e["platform"]["platform"].lower() == platform for e in endpoints.values()))
                    self.assertTrue(any(a["status"] == "vulnerable" and a["state_changed"]
                                        and a["variant"] == "expired_timestamp" for a in vulnerable["dast_results"]))
                    self.assertEqual(fixed["sast_findings"], [])
                    self.assertTrue(all(a["status"] == "rejected" for a in fixed["dast_results"]))
                finally:
                    server.should_exit = True
                    thread.join(timeout=5)
                    sock.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
