"""
samples/vulnerable_webhook.py

SAST 탐지 대상 파일.
아래 취약점이 의도적으로 포함되어 있습니다:

  [V1] 서명 검증 누락             — /webhook/no-verify
  [V2] == 로 서명 비교            — /webhook/timing-attack
  [V3] 취약한 해시 알고리즘       — /webhook/weak-hash-sha1, /webhook/weak-hash-md5
  [V4] 타임스탬프 검증 없음       — /webhook/no-timestamp
  [V5-a] 동일 파일 내 위임 결함   — /webhook/delegated  → _verify_delegated()
  [V5-b] 외부 파일 import 위임    — /webhook/delegated-external → utils_vulnerable.verify_signature()

Tier 1 상태 교차 검증:
  위조 요청 수락 시 _order_db 상태가 변경됩니다.
  Probe가 공격 전후 GET /orders/{order_id} 를 비교하면 변화를 감지할 수 있습니다.
"""

import hashlib
import hmac

from fastapi import FastAPI, Header, Request, HTTPException

# [V5-b] 외부 파일에서 결함 있는 함수를 import
from utils_vulnerable import verify_signature as external_verify

app = FastAPI()

SECRET = b"supersecretkey"

# 주문 상태 DB (Tier 1 상태 교차 검증용)
# key: order_id, value: 현재 상태 ("pending" | "paid" | "cancelled")
_order_db: dict[str, str] = {}


# [V1] 서명 검증 자체가 없음
#      위조 요청을 보내도 수락 → DB 상태 변경됨 (Tier 1 탐지 가능)
@app.post("/webhook/no-verify")
async def webhook_no_verify(request: Request):
    payload = await request.body()
    data = await request.json()

    # 서명을 전혀 확인하지 않고 상태 변경 → 위조 공격에 무방비
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")

    return {"status": "ok", "received": data}


# [V2] 타이밍 공격에 취약한 == 비교
@app.post("/webhook/timing-attack")
async def webhook_timing_attack(
    request: Request,
    x_hub_signature_256: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    computed = "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()

    # hmac.compare_digest 대신 == 사용 → 타이밍 공격 가능
    if x_hub_signature_256 == computed:
        data = await request.json()
        order_id = data.get("order_id", "unknown")
        _order_db[order_id] = data.get("status", "paid")
        return {"status": "ok"}

    raise HTTPException(status_code=401, detail="Invalid signature")


# [V3-a] 취약한 해시 알고리즘 — SHA1
@app.post("/webhook/weak-hash-sha1")
async def webhook_weak_hash_sha1(
    request: Request,
    x_hub_signature: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    # SHA1 은 충돌 공격에 취약 (GitHub 구 버전 방식)
    computed = "sha1=" + hmac.new(SECRET, payload, hashlib.sha1).hexdigest()

    if not hmac.compare_digest(x_hub_signature, computed):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# [V3-b] 취약한 해시 알고리즘 — MD5
@app.post("/webhook/weak-hash-md5")
async def webhook_weak_hash_md5(
    request: Request,
    x_signature: str = Header(None),
):
    payload = await request.body()

    if x_signature is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    # MD5 는 암호학적으로 완전히 파기된 알고리즘
    computed = "md5=" + hmac.new(SECRET, payload, hashlib.md5).hexdigest()

    if not hmac.compare_digest(x_signature, computed):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# [V4] 타임스탬프 검증 없음 → 재전송 공격에 무방비
@app.post("/webhook/no-timestamp")
async def webhook_no_timestamp(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_timestamp: str = Header(None),  # 받기는 하지만 검증 안 함
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    computed = "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(x_hub_signature_256, computed):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # x_timestamp 를 받았지만 현재 시각과 비교하지 않음 → 재전송 공격 가능
    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# [V5-a] 동일 파일 내 위임 — _verify_delegated() 에 == 결함
def _verify_delegated(signature: str, payload: bytes) -> bool:
    """위임된 검증 함수 — 내부에서 == 비교 사용 (타이밍 공격 취약)."""
    computed = "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    return signature == computed  # [V2] 와 동일한 결함


@app.post("/webhook/delegated")
async def webhook_delegated(
    request: Request,
    x_hub_signature_256: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    if not _verify_delegated(x_hub_signature_256, payload):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# [V5-b] 외부 파일 import 위임 — utils_vulnerable.verify_signature()
#         핸들러 코드만 보면 문제없어 보이지만,
#         import 추적 없이는 내부 == 결함을 발견할 수 없음
@app.post("/webhook/delegated-external")
async def webhook_delegated_external(
    request: Request,
    x_hub_signature_256: str = Header(None),
):
    payload = await request.body()

    if x_hub_signature_256 is None:
        raise HTTPException(status_code=401, detail="Missing signature")

    # 외부 함수 호출 — 이 줄만 보면 정상처럼 보임
    if not external_verify(x_hub_signature_256, payload, SECRET):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    order_id = data.get("order_id", "unknown")
    _order_db[order_id] = data.get("status", "paid")
    return {"status": "ok"}


# 상태 조회 엔드포인트 (Tier 1 Probe 테스트용)
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
