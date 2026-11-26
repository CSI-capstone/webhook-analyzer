"""네 로컬 시연 서버의 쇼핑 UI와 모의 발신기. 실제 결제·외부 서비스 연결 없음.

상품 금액은 서버에서 계산하고, 모의 발신기가 서명한 요청을 기존 수신 핸들러에
ASGI로 전달한다. 브라우저는 서명 키를 받거나 결제 완료 상태를 직접 설정하지 않는다.
"""
import base64
import hashlib
import hmac
import json
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.staticfiles import StaticFiles

ASSETS = Path(__file__).with_name("demo_web")
BRANDS = {
    "toss": {"name": "DKU GOODS", "subtitle": "단국 굿즈샵", "eyebrow": "CAMPUS COLLECTION / 2026",
             "title": "우리의 일상에,\n단국의 한 조각.", "description": "수업이 있는 날에도, 잠깐의 산책에도. 오래 함께할 캠퍼스 굿즈를 만나보세요.",
             "collection": "캠퍼스 에센셜", "payment": "토스페이먼츠 서명 형식", "badge": "CAMPUS EXCLUSIVE", "theme": "campus"},
    "stripe": {"name": "FORM & FIELD", "subtitle": "일상을 위한 작은 물건", "eyebrow": "OBJECTS FOR EVERYDAY",
               "title": "좋아하는 물건과\n보내는 하루.", "description": "고요한 책상, 따뜻한 커피, 가벼운 외출. 나의 리듬에 맞는 물건을 고릅니다.",
               "collection": "이번 주의 셀렉션", "payment": "Stripe 서명 형식", "badge": "THE EVERYDAY EDIT", "theme": "studio"},
    "slack": {"name": "COMMON TEAM", "subtitle": "함께 일하는 사람들의 스토어", "eyebrow": "A LITTLE MORE TEAM SPIRIT",
              "title": "좋은 팀의 취향을\n함께 나누세요.", "description": "새로운 동료의 첫날부터 프로젝트의 마지막 날까지. 우리 팀을 위한 작은 선물.",
              "collection": "팀을 위한 굿즈", "payment": "모의 결제 후 Slack 형식 알림", "badge": "MADE FOR YOUR TEAM", "theme": "team"},
    "generic": {"name": "NEIGHBOR STORE", "subtitle": "가까이 두는 물건들", "eyebrow": "SMALL THINGS, GOOD DAYS",
                "title": "매일 쓰는 물건에\n작은 즐거움을.", "description": "특별한 날이 아니어도 괜찮아요. 편안하게 고르고 오래 쓰는 우리 동네 상점.",
                "collection": "오늘의 발견", "payment": "일반 HMAC 서명", "badge": "YOUR DAILY FAVORITES", "theme": "neighborhood"},
}

LIFESTYLE_PRODUCTS = [
    {"id": "F001", "name": "데일리 세라믹 머그", "price": 24000, "stock": 32, "kind": "mug", "category": "리빙", "tag": "BEST", "tone": "#79917f"},
    {"id": "F002", "name": "캔버스 데일리 백", "price": 32000, "stock": 20, "kind": "bag", "category": "가방", "tag": "NEW", "tone": "#b79874"},
    {"id": "F003", "name": "슬로우 데이 후디", "price": 59000, "stock": 18, "kind": "hoodie", "category": "의류", "tag": "", "tone": "#698171"},
    {"id": "F004", "name": "생각을 담는 노트", "price": 12000, "stock": 60, "kind": "notebook", "category": "문구", "tag": "", "tone": "#c68764"},
    {"id": "F005", "name": "아날로그 펜 세트", "price": 9000, "stock": 50, "kind": "pen", "category": "문구", "tag": "", "tone": "#747b69"},
    {"id": "F006", "name": "작은 쉼표 기프트 박스", "price": 39000, "stock": 15, "kind": "box", "category": "선물", "tag": "GIFT", "tone": "#ad876d"},
]
TEAM_PRODUCTS = [
    {"id": "T001", "name": "팀 스피릿 후디", "price": 49000, "stock": 25, "kind": "hoodie", "category": "의류", "tag": "BEST", "tone": "#766390"},
    {"id": "T002", "name": "프로젝트 텀블러", "price": 27000, "stock": 40, "kind": "mug", "category": "리빙", "tag": "NEW", "tone": "#6d8e8b"},
    {"id": "T003", "name": "웰컴 온보딩 키트", "price": 45000, "stock": 20, "kind": "box", "category": "선물", "tag": "TEAM PICK", "tone": "#a084ae"},
    {"id": "T004", "name": "미팅 노트 두 권 세트", "price": 14000, "stock": 50, "kind": "notebook", "category": "문구", "tag": "", "tone": "#c98e6c"},
    {"id": "T005", "name": "라이트 워크 에코백", "price": 19000, "stock": 30, "kind": "bag", "category": "가방", "tag": "", "tone": "#8e9d83"},
    {"id": "T006", "name": "아이디어 펜 세트", "price": 8000, "stock": 80, "kind": "pen", "category": "문구", "tag": "", "tone": "#826a9c"},
]


def _campus_catalog(products):
    kinds = ["hoodie", "mug", "bag", "pen", "notebook"]
    tones = ["#334b73", "#8babb2", "#b09a78", "#6a7d95", "#a08a75"]
    categories = ["의류", "리빙", "가방", "문구", "문구"]
    return [{"id": key, **value, "kind": kinds[i % len(kinds)], "tone": tones[i % len(tones)],
             "category": categories[i % len(categories)], "tag": "BEST" if i == 0 else ("NEW" if i == 1 else "")}
            for i, (key, value) in enumerate(products.items())]


def render_demo_page(platform):
    # 키·개인정보를 넣지 않는 공개 UI 설정만 삽입한다.
    config = {"platform": platform, **BRANDS[platform]}
    encoded = json.dumps(config, ensure_ascii=False).replace("<", "\\u003c")
    return (ASSETS / "storefront.html").read_text(encoding="utf-8").replace("__DEMO_CONFIG__", encoded)


async def _dispatch(app, path, body, headers):
    """고정된 로컬 수신 경로에 실제 ASGI 요청을 전달한다. 외부 URL 요청은 하지 않는다."""
    sent = False
    messages = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
             "method": "POST", "root_path": "", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [(b"host", b"localhost")] + [(k.lower().encode(), v.encode()) for k, v in headers.items()],
             "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 0)}
    await app(scope, receive, send)
    status = next((m["status"] for m in messages if m["type"] == "http.response.start"), 500)
    response = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    try:
        decoded = json.loads(response)
    except (ValueError, UnicodeError):
        decoded = {"detail": response.decode(errors="replace")[:1000]}
    return status, decoded


def _signed_event(platform, order, secret, scenario):
    timestamp = int(time.time()) - (360 if scenario == "expired" else 0)
    iso = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")
    oid = order["order_id"]
    amount = order["amount"]
    if platform == "toss":
        event = {"eventType": "PAYMENT_STATUS_CHANGED", "createdAt": iso,
                 "data": {"paymentKey": "demo_payment_" + oid, "orderId": oid, "status": "DONE", "totalAmount": amount}}
    elif platform == "stripe":
        event = {"id": "evt_demo_" + uuid.uuid4().hex, "object": "event", "type": "payment_intent.succeeded", "created": timestamp,
                 "livemode": False, "data": {"object": {"id": "pi_demo_" + oid, "amount": amount, "currency": "krw",
                 "status": "succeeded", "metadata": {"order_id": oid}}}}
    elif platform == "slack":
        event = {"type": "event_callback", "team_id": "T_DEMO_TEAM", "event_id": "Ev" + uuid.uuid4().hex,
                 "event_time": timestamp, "event": {"type": "message", "user": "U_DEMO_SENDER", "channel": "C_TEAM_ORDERS",
                 "text": f"팀 굿즈 주문 #{oid[:8]} 알림 · {order['product_name']}", "ts": str(timestamp)}, "order_id": oid}
    else:
        event = {"event": "payment.completed", "order_id": oid, "status": "paid", "amount": amount, "timestamp": timestamp}
    body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if platform == "toss":
        signature_key = "TossPayments-Webhook-Signature"
        digest = hmac.new(secret, body + b":" + iso.encode(), hashlib.sha256).digest()
        headers.update({signature_key: "v1:" + base64.b64encode(digest).decode(),
                        "TossPayments-Webhook-Transmission-Time": iso, "TossPayments-Webhook-Transmission-Id": uuid.uuid4().hex})
    elif platform == "stripe":
        signature_key = "Stripe-Signature"
        digest = hmac.new(secret, str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()
        headers[signature_key] = f"t={timestamp},v1={digest}"
    elif platform == "slack":
        signature_key = "X-Slack-Signature"
        digest = hmac.new(secret, f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
        headers.update({signature_key: "v0=" + digest, "X-Slack-Request-Timestamp": str(timestamp)})
    else:
        signature_key = "X-Signature"
        headers.update({signature_key: "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest(), "X-Timestamp": str(timestamp)})
    if scenario == "invalid_signature":
        headers[signature_key] = "invalid-signature-for-local-demo"
    elif scenario == "missing_signature":
        headers.pop(signature_key)
    return body, headers


def install_demo_ui(app, orders, platform, secret, webhook_path, *, products=None, fixed_path=None):
    catalog = _campus_catalog(products) if products is not None else [dict(p) for p in (TEAM_PRODUCTS if platform == "slack" else LIFESTYLE_PRODUCTS)]
    catalog_by_id = {p["id"]: p for p in catalog}
    logs = deque(maxlen=100)
    allowed_paths = [webhook_path] + ([fixed_path] if fixed_path else [])
    app.mount("/demo-assets", StaticFiles(directory=str(ASSETS)), name="demo-assets")

    def create_order(data, *, source="storefront"):
        items = data.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= 20:
            raise HTTPException(422, "상품을 한 개 이상 선택해 주세요.")
        lines = []
        seen = set()
        for item in items:
            if not isinstance(item, dict) or item.get("id") not in catalog_by_id:
                raise HTTPException(422, "등록되지 않은 상품입니다.")
            product = catalog_by_id[item["id"]]
            if product["id"] in seen:
                raise HTTPException(422, "같은 상품은 수량으로 합쳐 주세요.")
            seen.add(product["id"])
            quantity = item.get("quantity", 1)
            if type(quantity) is not int or not 1 <= quantity <= min(product["stock"], 20):
                raise HTTPException(422, "상품 수량을 확인해 주세요.")
            lines.append({"id": product["id"], "name": product["name"], "kind": product["kind"], "tone": product["tone"],
                          "quantity": quantity, "unit_price": product["price"], "line_total": product["price"] * quantity})
        subtotal = sum(line["line_total"] for line in lines)
        delivery = data.get("delivery", "pickup")
        if delivery not in {"pickup", "shipping"}:
            raise HTTPException(422, "수령 방법을 확인해 주세요.")
        shipping = 0 if delivery == "pickup" or subtotal >= 50000 else 3000
        customer = data.get("customer") or {}
        if not isinstance(customer, dict):
            raise HTTPException(422, "주문자 정보가 올바르지 않습니다.")
        name = str(customer.get("name", "체험 고객")).strip()[:40] or "체험 고객"
        email = str(customer.get("email", "demo@example.test")).strip()[:100]
        address = str(customer.get("address", "시연용 가상 수령지")).strip()[:200]
        if "@" not in email:
            raise HTTPException(422, "이메일 형식을 확인해 주세요.")
        oid = uuid.uuid4().hex
        orders[oid] = {"order_id": oid, "status": "pending", "payment_status": "pending", "provider_status": "not_requested",
                       "items": lines, "product_name": lines[0]["name"] + (f" 외 {len(lines) - 1}종" if len(lines) > 1 else ""),
                       "subtotal": subtotal, "shipping_fee": shipping, "amount": subtotal + shipping,
                       "delivery": delivery, "customer": {"name": name, "email": email, "address": address},
                       "created_at": datetime.now(timezone.utc).isoformat(), "source": source}
        return orders[oid]

    @app.get("/demo/state")
    async def demo_state():
        rows = list(orders.values())
        display_rows = []
        for row in reversed(rows[-100:]):
            display = dict(row)
            if platform != "slack":
                display["payment_status"] = "paid" if row.get("status") == "paid" else "pending"
            display_rows.append(display)
        return {"platform": platform, "brand": BRANDS[platform], "products": catalog, "orders": display_rows,
                "logs": list(reversed(logs)), "paths": allowed_paths,
                "stats": {"total": len(rows), "processed": sum(row.get("status") in {"paid", "processed"} for row in rows),
                          "pending": sum(row.get("status") == "pending" for row in rows)}}

    @app.post("/demo/order")
    async def demo_order(request: Request):
        data = await request.json()
        if not isinstance(data, dict):
            raise HTTPException(422, "주문 정보가 올바르지 않습니다.")
        return dict(create_order(data))

    async def submit(order_id, scenario, path, *, approve_payment=False):
        if order_id not in orders or orders[order_id].get("source") not in {"storefront", "security_demo"}:
            raise HTTPException(404, "화면에서 만든 주문을 선택해 주세요.")
        if path not in allowed_paths or scenario not in {"normal", "expired", "invalid_signature", "missing_signature"}:
            raise HTTPException(422, "지원하지 않는 시연 요청입니다.")
        order = orders[order_id]
        if order["status"] != "pending":
            raise HTTPException(409, "이미 처리된 주문입니다. 새 시험 주문을 만들어 주세요.")
        before = order["status"]
        if approve_payment:
            order["provider_status"] = "approved"  # 내장 모의 결제사의 승인 결과
            if platform == "slack":
                # Slack 콜백은 결제를 승인하지 않고 후속 주문 알림만 처리한다.
                order["payment_status"] = "paid"
        body, headers = _signed_event(platform, order, secret, scenario)
        code, response = await _dispatch(app, path, body, headers)
        after = order["status"]
        if platform != "slack" and after == "paid":
            order["payment_status"] = "paid"
        log = {"id": uuid.uuid4().hex, "order_id": order_id, "scenario": scenario, "path": path,
               "http_status": code, "before": before, "after": after, "state_changed": before != after,
               "at": datetime.now(timezone.utc).isoformat(), "request_headers": headers,
               "request_body": json.loads(body), "response": response, "payment_approved": approve_payment}
        logs.append(log)
        return {"order": dict(order), "delivery": log}

    @app.post("/demo/pay")
    async def demo_pay(request: Request):
        data = await request.json()
        if not isinstance(data, dict) or data.get("method") not in {"demo_card", "demo_bank"}:
            raise HTTPException(422, "시연용 결제 수단을 선택해 주세요.")
        return await submit(str(data.get("order_id", "")), "normal", webhook_path, approve_payment=True)

    @app.post("/demo/send")
    async def demo_send(request: Request):
        data = await request.json()
        if not isinstance(data, dict):
            raise HTTPException(422, "요청 정보가 올바르지 않습니다.")
        if data.get("new_order"):
            order = create_order({"items": [{"id": catalog[0]["id"], "quantity": 1}], "delivery": "pickup"}, source="security_demo")
            order_id = order["order_id"]
        else:
            order_id = str(data.get("order_id", ""))
        return await submit(order_id, data.get("scenario", "normal"), data.get("path", webhook_path))

    @app.post("/demo/reset")
    async def demo_reset():
        orders.clear()
        logs.clear()
        return {"ok": True}
