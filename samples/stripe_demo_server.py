"""Stripe 서명 형식의 로컬 모의 수신 서버. 실제 결제·외부 API 호출 없음.

uvicorn samples.stripe_demo_server:app --host 127.0.0.1 --port 8002
분석기에 이 파일을 업로드하고 시크릿 stripe-demo-secret-2026을 입력한다.
두 경로는 시간 검증의 유무를 비교하는 예제이며 운영용 구현이 아니다.
"""
import hashlib
import hmac
import json
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from samples.demo_ui import install_demo_ui, render_demo_page
from fastapi.responses import HTMLResponse

app = FastAPI(title="HookLens Stripe 모의 서버")
WEBHOOK_SECRET = b"stripe-demo-secret-2026"  # 공개된 로컬 시연용 키
TIMESTAMP_TOLERANCE = 300
_orders: dict[str, dict] = {}


@app.get("/")
async def index():
    return HTMLResponse(render_demo_page("stripe"))


@app.post("/orders")
async def create_order():
    order_id = uuid.uuid4().hex
    _orders[order_id] = {"order_id": order_id, "status": "pending"}
    return dict(_orders[order_id])


@app.get("/orders/{order_id}")
async def query_order(order_id: str):
    if order_id not in _orders:
        raise HTTPException(404, "시험 주문 없음")
    return dict(_orders[order_id])


def _parse_stripe_header(header: str | None):
    if not header:
        raise HTTPException(401, "서명 헤더 없음")
    parts = {}
    for item in header.split(","):
        key, separator, value = item.strip().partition("=")
        if separator:
            parts[key] = value
    timestamp_str = parts.get("t", "")
    received_signature = parts.get("v1", "")
    try:
        timestamp = int(timestamp_str)
    except ValueError:
        raise HTTPException(401, "시간값 형식 오류")
    if not received_signature or not received_signature.isascii():
        raise HTTPException(401, "서명값 형식 오류")
    return timestamp_str, timestamp, received_signature


def _apply_event(payload: bytes, content_type: str):
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "JSON만 허용")
    try:
        event = json.loads(payload)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "JSON 형식 오류")
    if not isinstance(event, dict):
        raise HTTPException(400, "JSON 객체만 허용")
    payment = event.get("data", {}).get("object", {}) if isinstance(event.get("data"), dict) else {}
    metadata = payment.get("metadata", {}) if isinstance(payment, dict) else {}
    # 스토어 주문은 결제 객체 metadata로 연결한다. order_id는 분석기용 보조 필드이다.
    order_id = str((metadata.get("order_id") if isinstance(metadata, dict) else None) or event.get("order_id", ""))
    linked = order_id in _orders
    if linked:
        if _orders[order_id].get("source") in {"storefront", "security_demo"}:
            if event.get("type") != "payment_intent.succeeded" or payment.get("amount") != _orders[order_id]["amount"]:
                raise HTTPException(400, "결제 이벤트 또는 주문 금액 불일치")
        _orders[order_id]["status"] = "paid"
    # Probe는 아직 생성하지 않은 ID를 사용할 수 있다. 미연결 이벤트도 수락한다.
    return {"accepted": True, "linked_to_test_order": linked}


@app.post("/webhook/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(None, alias="Stripe-Signature"),
):
    """의도한 결함: 서명은 확인하지만 서명된 시간값의 만료는 확인하지 않는다."""
    payload = await request.body()
    timestamp_str, timestamp, received_signature = _parse_stripe_header(stripe_signature)
    signed_payload = timestamp_str.encode() + b"." + payload
    expected = hmac.new(WEBHOOK_SECRET, signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received_signature, expected):
        raise HTTPException(401, "서명 불일치")
    # WHSEC-004: timestamp를 받았지만 현재 시각과 비교하지 않음.
    return _apply_event(payload, request.headers.get("content-type", ""))


@app.post("/webhook/stripe-fixed")
async def stripe_fixed_webhook(
    request: Request,
    stripe_signature: str | None = Header(None, alias="Stripe-Signature"),
):
    """비교용 보완 예제: 서명된 시간값을 허용 시간과 함께 확인한다."""
    payload = await request.body()
    timestamp_str, timestamp, received_signature = _parse_stripe_header(stripe_signature)
    signed_payload = timestamp_str.encode() + b"." + payload
    expected = hmac.new(WEBHOOK_SECRET, signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received_signature, expected):
        raise HTTPException(401, "서명 불일치")
    if abs(time.time() - timestamp) > TIMESTAMP_TOLERANCE:
        raise HTTPException(401, "허용 시간을 벗어난 요청")
    return _apply_event(payload, request.headers.get("content-type", ""))


# 화면과 모의 발신기만 설치하며, 위 웹훅 검증 함수는 그대로 분석할 수 있습니다.
install_demo_ui(app, _orders, "stripe", WEBHOOK_SECRET, "/webhook/stripe", fixed_path="/webhook/stripe-fixed")
