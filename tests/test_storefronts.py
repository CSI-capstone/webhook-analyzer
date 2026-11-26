"""네 스토어의 주문·모의 결제·실제 수신 처리와 보안 시험을 검사한다."""
import base64
import hashlib
import hmac
import json
import unittest

from fastapi.testclient import TestClient
from samples import generic_shop_server, shop_server, slack_demo_server, stripe_demo_server

CASES = (("toss", shop_server, "paid"), ("stripe", stripe_demo_server, "paid"),
         ("slack", slack_demo_server, "processed"), ("generic", generic_shop_server, "paid"))


class StorefrontTests(unittest.TestCase):
    def each(self):
        for platform, module, final in CASES:
            yield platform, module, final, TestClient(module.app)

    def order(self, client, **changes):
        product = client.get("/demo/state").json()["products"][0]
        data = {"items": [{"id": product["id"], "quantity": 1}], "delivery": "pickup",
                "customer": {"name": "시연 고객", "email": "demo@example.test"}, **changes}
        response = client.post("/demo/order", json=data)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json(), product

    def test_pages_and_local_assets_exist_without_exposing_keys(self):
        themes = set()
        for platform, module, _, client in self.each():
            with client, self.subTest(platform=platform):
                root = client.get("/")
                self.assertEqual(root.status_code, 200)
                self.assertIn("text/html", root.headers["content-type"])
                self.assertIn("checkoutDialog", root.text)
                self.assertIn("paymentDialog", root.text)
                self.assertNotIn(module.WEBHOOK_SECRET.decode(), root.text)
                config = json.loads(root.text.split('id="demo-config" type="application/json">')[1].split('</script>')[0])
                themes.add(config["theme"])
                state = client.get("/demo/state").json()
                self.assertGreaterEqual(len(state["products"]), 5)
                self.assertNotIn(module.WEBHOOK_SECRET.decode(), json.dumps(state))
                for asset in ("storefront.css", "storefront.js", "products.svg"):
                    self.assertEqual(client.get("/demo-assets/" + asset).status_code, 200)
        self.assertEqual(len(themes), 4)

    def test_prices_are_computed_on_server_and_delivery_fee_is_applied(self):
        for platform, _, _, client in self.each():
            with client, self.subTest(platform=platform):
                product = client.get("/demo/state").json()["products"][0]
                response = client.post("/demo/order", json={"items": [{"id": product["id"], "quantity": 1, "price": 1}],
                                                          "amount": 1, "delivery": "shipping"})
                self.assertEqual(response.status_code, 200)
                order = response.json()
                self.assertEqual(order["subtotal"], product["price"])
                self.assertEqual(order["shipping_fee"], 3000 if product["price"] < 50000 else 0)
                self.assertEqual(order["amount"], product["price"] + order["shipping_fee"])
                self.assertEqual(order["status"], "pending")

    def test_invalid_catalog_and_quantity_inputs_are_rejected(self):
        for platform, _, _, client in self.each():
            with client:
                product = client.get("/demo/state").json()["products"][0]
                for items in ([], [{"id": "not-a-product", "quantity": 1}], [{"id": product["id"], "quantity": 0}],
                              [{"id": product["id"], "quantity": True}], [{"id": product["id"], "quantity": 999}],
                              [{"id": product["id"], "quantity": 1}] * 2):
                    with self.subTest(platform=platform, items=items):
                        self.assertEqual(client.post("/demo/order", json={"items": items}).status_code, 422)

    def test_mock_approval_invokes_real_receiver_and_does_not_allow_double_checkout(self):
        for platform, _, final, client in self.each():
            with client, self.subTest(platform=platform):
                order, _ = self.order(client)
                response = client.post("/demo/pay", json={"order_id": order["order_id"], "method": "demo_card"})
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                self.assertEqual(result["delivery"]["http_status"], 200)
                self.assertEqual(result["delivery"]["before"], "pending")
                self.assertEqual(result["delivery"]["after"], final)
                self.assertTrue(result["delivery"]["state_changed"])
                self.assertEqual(result["order"]["payment_status"], "paid")
                self.assertEqual(client.get(f"/orders/{order['order_id']}").json()["status"], final)
                self.assertEqual(client.post("/demo/pay", json={"order_id": order["order_id"], "method": "demo_card"}).status_code, 409)

    def test_bad_signature_requests_do_not_mark_orders_paid_or_processed(self):
        for platform, _, _, client in self.each():
            with client:
                for scenario in ("invalid_signature", "missing_signature"):
                    with self.subTest(platform=platform, scenario=scenario):
                        response = client.post("/demo/send", json={"new_order": True, "scenario": scenario})
                        self.assertEqual(response.status_code, 200, response.text)
                        result = response.json()
                        self.assertEqual(result["delivery"]["http_status"], 401)
                        self.assertEqual(result["order"]["status"], "pending")
                        self.assertEqual(result["order"]["payment_status"], "pending")
                        self.assertFalse(result["delivery"]["state_changed"])

    def test_expired_requests_expose_original_flaw_but_fixed_paths_reject(self):
        for platform, _, final, client in self.each():
            with client, self.subTest(platform=platform):
                result = client.post("/demo/send", json={"new_order": True, "scenario": "expired"}).json()
                self.assertEqual(result["delivery"]["http_status"], 200)
                self.assertEqual(result["delivery"]["after"], final)
                if platform == "slack":
                    # Slack 메시지를 수락해도 결제를 승인한 것으로 표현하지 않는다.
                    self.assertEqual(result["order"]["payment_status"], "pending")
                paths = client.get("/demo/state").json()["paths"]
                if len(paths) > 1:
                    fixed = client.post("/demo/send", json={"new_order": True, "scenario": "expired", "path": paths[1]}).json()
                    self.assertEqual(fixed["delivery"]["http_status"], 401)
                    self.assertEqual(fixed["delivery"]["after"], "pending")

    def test_demo_sender_cannot_target_unrelated_or_external_paths(self):
        for platform, _, _, client in self.each():
            with client, self.subTest(platform=platform):
                order, _ = self.order(client)
                for path in ("https://example.test/collect", "/demo/reset", "/orders"):
                    response = client.post("/demo/send", json={"order_id": order["order_id"], "path": path})
                    self.assertEqual(response.status_code, 422)

    def test_ui_order_payment_amount_mismatch_is_rejected_even_with_valid_signature(self):
        for platform, module, _, client in self.each():
            if platform == "slack":
                continue
            with client, self.subTest(platform=platform):
                order, _ = self.order(client)
                from samples.demo_ui import _signed_event
                body, headers = _signed_event(platform, order, module.WEBHOOK_SECRET, "normal")
                payload = json.loads(body)
                if platform == "toss":
                    payload["data"]["totalAmount"] = 1
                elif platform == "stripe":
                    payload["data"]["object"]["amount"] = 1
                else:
                    payload["amount"] = 1
                body = json.dumps(payload, ensure_ascii=False).encode()
                if platform == "toss":
                    signed = body + b":" + headers["TossPayments-Webhook-Transmission-Time"].encode()
                    headers["TossPayments-Webhook-Signature"] = "v1:" + base64.b64encode(hmac.new(module.WEBHOOK_SECRET, signed, hashlib.sha256).digest()).decode()
                elif platform == "stripe":
                    timestamp = headers["Stripe-Signature"].split(",")[0].split("=")[1]
                    headers["Stripe-Signature"] = "t=" + timestamp + ",v1=" + hmac.new(module.WEBHOOK_SECRET, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
                else:
                    headers["X-Signature"] = "sha256=" + hmac.new(module.WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
                path = client.get("/demo/state").json()["paths"][0]
                response = client.post(path, content=body, headers=headers)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(client.get(f"/orders/{order['order_id']}").json()["status"], "pending")


if __name__ == "__main__":
    unittest.main(verbosity=2)
