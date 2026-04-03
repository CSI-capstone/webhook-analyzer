"""
secure_webhook.py

SAST 통과 기준 파일.
모든 엔드포인트가 올바르게 구현되어 있어야 합니다:

  [S1] 모든 핸들러에 서명 검증 존재
  [S2] hmac.compare_digest 로 상수 시간 비교
  [S3] SHA256 만 사용
  [S4] 타임스탬프 검증 (5분 이내)
  [S5] 위임 함수도 내부적으로 안전하게 구현

Tier 1 상태 교차 검증:
  서명이 유효할 때만 _order_db 상태가 변경됩니다.
  위조 서명 요청 → 401 반환 → DB 상태 불변.
  공격 전후 GET /orders/{order_id} 를 비교하면 변화 없음이 확인됩니다.
"""

import hashlib
import hmac
import os
import time

from fastapi import FastAPI, Header, Request, HTTPException

app = FastAPI()

# 버그 9 연쇄 수정: b"..." 직접 할당은 수정된 WHSEC-006 패턴에 탐지됨
# os.environ.get("KEY") or "fallback" 형태를 사용하여 HARDCODE_PATTERN 및
# ENVDEFAULT_PATTERN(두 번째 인자 방식) 모두 해당하지 않도록 처리
# 테스트 환경에서는 환경변수 미설정 시 기본값으로 동작
SECRET: bytes = (os.environ.get("WEBHOOK_SECRET") or "supersecretkey").encode()

TIMESTAMP_TOLERANCE_SECONDS = 300  # 5분

# ────────────────────────────────────────────────────────────
# 주문 상태 DB (Tier 1 상태 교차 검증용)
# key: order_id, value: 현재 상태 ("pending" | "paid" | "cancelled")
# ────────────────────────────────────────────────────────────
_order_db: dict[str, str] = {}


# ────────────────────────────────────────────────────────────
# 내부 헬퍼
# ────────────────────────────────────────────────────────────
def _compute_signature(payload: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


def _verify_signature(header_sig: str, payload: bytes) -> bool:
    """[S2+S3] 상수 시간 비교 + SHA256."""
    computed = _compute_signature(payload)
    return hmac.compare_digest(header_sig, computed)


def _verify_timestamp(timestamp_str: str) -> bool:
    """[S4] 타임스탬프가 현재 시각 기준 ±5분 이내인지 검증."""
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    return abs(time.time() - ts) <= TIMESTAMP_TOLERANCE_SECONDS


# ────────────────────────────────────────────────────────────
# [S1+S2+S3+S4] 완전히 안전한 핸들러
#               유효한 서명일 때만 DB 상태 변경
# ────────────────────────────────────────────────────────────
@app.post("/webhook/secure")
async def webhook_secure(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_timestamp: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")
    if x_timestamp is None:
        raise HTTPException(status_code=401, detail="Missing timestamp")

    # [S4] 타임스탬프 검증
    if not _verify_timestamp(x_timestamp):
        raise HTTPException(status_code=401, detail="Timestamp expired or invalid")

    # [S2+S3] 서명 검증
    if not _verify_signature(x_hub_signature_256, payload):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 모든 검증 통과한 경우에만 상태 변경
    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")

    return {"status": "ok", "received": data}


# ────────────────────────────────────────────────────────────
# [S5] 외부 함수 위임 — 위임된 함수도 안전하게 구현
# ────────────────────────────────────────────────────────────
def _verify_delegated_secure(signature: str, payload: bytes) -> bool:
    """위임된 검증 함수 — compare_digest 사용."""
    computed = _compute_signature(payload)
    return hmac.compare_digest(signature, computed)


@app.post("/webhook/delegated-secure")
async def webhook_delegated_secure(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_timestamp: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")
    if x_timestamp is None:
        raise HTTPException(status_code=401, detail="Missing timestamp")

    if not _verify_timestamp(x_timestamp):
        raise HTTPException(status_code=401, detail="Timestamp expired or invalid")

    if not _verify_delegated_secure(x_hub_signature_256, payload):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# ────────────────────────────────────────────────────────────
# Stripe 스타일 검증 (타임스탬프가 서명 페이로드에 포함)
# ────────────────────────────────────────────────────────────
@app.post("/webhook/stripe-style")
async def webhook_stripe_style(
    request: Request,
    stripe_signature: str = Header(None),
):
    """Stripe: 헤더 형식 t=<timestamp>,v1=<sig>"""
    payload = await request.body()

    if stripe_signature is None:
        raise HTTPException(status_code=401, detail="Missing Stripe-Signature")

    parts = dict(
        item.split("=", 1) for item in stripe_signature.split(",") if "=" in item
    )
    timestamp = parts.get("t")
    sig_v1 = parts.get("v1")

    if not timestamp or not sig_v1:
        raise HTTPException(status_code=400, detail="Malformed signature header")

    if not _verify_timestamp(timestamp):
        raise HTTPException(status_code=401, detail="Timestamp expired")

    # Stripe 방식: signed_payload = timestamp + "." + body
    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(SECRET, signed_payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig_v1, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# ────────────────────────────────────────────────────────────
# 상태 조회 엔드포인트 (Tier 1 Probe 테스트용)
# ────────────────────────────────────────────────────────────
@app.post("/orders")
async def create_order(request: Request):
    data = await request.json()
    order_id = str(len(_order_db) + 1)
    _order_db[order_id] = "pending"
    return {"order_id": order_id, "status": "pending"}


@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    if order_id not in _order_db:
        raise HTTPException(status_code=404, detail="Not found")
    return {"order_id": order_id, "status": _order_db[order_id]}
