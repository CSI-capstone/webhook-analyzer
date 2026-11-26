"""Slack 서명 형식의 로컬 모의 수신 서버. 실제 워크스페이스 연결 없음.

uvicorn samples.slack_demo_server:app --host 127.0.0.1 --port 8003
분석기에 이 파일을 업로드하고 시크릿 slack-demo-secret-2026을 입력한다.
/orders는 분석기와 연결하는 모의 작업 상태 API이며 실제 Slack API가 아니다.
"""
import hashlib
import hmac
import json
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from samples.demo_ui import install_demo_ui, render_demo_page
from fastapi.responses import HTMLResponse

app = FastAPI(title="HookLens Slack 모의 서버")
WEBHOOK_SECRET = b"slack-demo-secret-2026"  # 공개된 로컬 시연용 키
TIMESTAMP_TOLERANCE = 300
_orders: dict[str, dict] = {}


@app.get("/")
async def index():
    return HTMLResponse(render_demo_page("slack"))


@app.post("/orders")
async def create_order():
    task_id = uuid.uuid4().hex
    _orders[task_id] = {"order_id": task_id, "status": "pending"}
    return dict(_orders[task_id])


@app.get("/orders/{order_id}")
async def query_order(order_id: str):
    if order_id not in _orders:
        raise HTTPException(404, "시험 작업 없음")
    return dict(_orders[order_id])


def _apply_event(payload: bytes, content_type: str):
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "JSON만 허용")
    try:
        event = json.loads(payload)
    except (ValueError, UnicodeError):
        raise HTTPException(400, "JSON 형식 오류")
    if not isinstance(event, dict):
        raise HTTPException(400, "JSON 객체만 허용")
    task_id = str(event.get("order_id", ""))
    linked = task_id in _orders
    if linked:
        _orders[task_id]["status"] = "processed"
    return {"accepted": True, "linked_to_test_task": linked}


@app.post("/webhook/slack")
async def slack_webhook(
    request: Request,
    x_slack_signature: str | None = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str | None = Header(None, alias="X-Slack-Request-Timestamp"),
):
    """의도한 시연용 결함: 일반 서명 비교와 시간 만료 검사 누락."""
    payload = await request.body()
    if not x_slack_signature or not x_slack_request_timestamp:
        raise HTTPException(401, "서명 또는 시간 헤더 없음")
    if not x_slack_signature.isascii():
        raise HTTPException(401, "서명값 형식 오류")
    try:
        timestamp = int(x_slack_request_timestamp)
    except ValueError:
        raise HTTPException(401, "시간값 형식 오류")
    signed_payload = b"v0:" + x_slack_request_timestamp.encode() + b":" + payload
    expected = "v0=" + hmac.new(WEBHOOK_SECRET, signed_payload, hashlib.sha256).hexdigest()
    # WHSEC-002: 일반 비교. 시간 측정에 의한 악용 성공을 입증하는 예제는 아니다.
    if x_slack_signature != expected:
        raise HTTPException(401, "서명 불일치")
    # WHSEC-004: timestamp와 현재 시각의 차이를 확인하지 않음.
    return _apply_event(payload, request.headers.get("content-type", ""))


@app.post("/webhook/slack-fixed")
async def slack_fixed_webhook(
    request: Request,
    x_slack_signature: str | None = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str | None = Header(None, alias="X-Slack-Request-Timestamp"),
):
    """비교용 보완 예제: 상수 시간 서명 비교와 시간 만료 검사를 적용한다."""
    payload = await request.body()
    if not x_slack_signature or not x_slack_request_timestamp:
        raise HTTPException(401, "서명 또는 시간 헤더 없음")
    if not x_slack_signature.isascii():
        raise HTTPException(401, "서명값 형식 오류")
    try:
        timestamp = int(x_slack_request_timestamp)
    except ValueError:
        raise HTTPException(401, "시간값 형식 오류")
    signed_payload = b"v0:" + x_slack_request_timestamp.encode() + b":" + payload
    expected = "v0=" + hmac.new(WEBHOOK_SECRET, signed_payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(x_slack_signature, expected):
        raise HTTPException(401, "서명 불일치")
    if abs(time.time() - timestamp) > TIMESTAMP_TOLERANCE:
        raise HTTPException(401, "허용 시간을 벗어난 요청")
    return _apply_event(payload, request.headers.get("content-type", ""))


# 화면과 모의 발신기만 설치하며, 위 웹훅 검증 함수는 그대로 분석할 수 있습니다.
install_demo_ui(app, _orders, "slack", WEBHOOK_SECRET, "/webhook/slack", fixed_path="/webhook/slack-fixed")
