"""
samples/generic_shop_server.py

  단국 굿즈샵 — 모의 HMAC 결제 연동 서버 (시연용)

[시연 시나리오]
  이 서버는 단국대 굿즈를 판매하는 온라인 쇼핑몰 개발자가
  모의 HMAC 결제 웹훅을 연동한 상황을 가정합니다.

  "개발은 다 됐는데... 혹시 보안에 문제가 있지 않을까?"
  → HookLens에 코드를 입력하면 취약점을 자동으로 찾아줍니다.

[HookLens 입력값]
  소스코드         : samples/generic_shop_server.py (이 파일)
  웹훅 URL         : http://localhost:8004
  HMAC 시크릿 키   : generic-demo-secret-2026
  상태 생성 경로   : /orders
  상태 조회 경로   : /orders/{id}

[예상 탐지 결과]
  WHSEC-002  HIGH    - 서명 비교에 == 사용 (타이밍 공격 취약)
  WHSEC-004  MEDIUM  - x-timestamp 헤더를 받지만 만료 검증 안 함

[실행 방법]
  pip install fastapi uvicorn
  uvicorn samples.generic_shop_server:app --port 8004 --reload
"""

import base64
import hashlib
import hmac

from fastapi import FastAPI, Header, HTTPException, Request
from samples.demo_ui import install_demo_ui, render_demo_page
from fastapi.responses import HTMLResponse

# 앱 설정
app = FastAPI(
    title="단국 굿즈샵",
    description="모의 HMAC 결제 연동 쇼핑몰 (HookLens 시연용)",
    version="1.0.0",
)

# 웹훅 검증용 시크릿 키 (실제 서비스에서는 환경변수로 관리해야 합니다)
WEBHOOK_SECRET = b"generic-demo-secret-2026"

# 상품 목록
PRODUCTS = {
    "P001": {"name": "단국대 후드티 (네이비)",  "price": 45_000, "stock": 30},
    "P002": {"name": "단국대 스텐 텀블러",      "price": 28_000, "stock": 50},
    "P003": {"name": "단국대 캔버스 토트백",    "price": 18_000, "stock": 40},
    "P004": {"name": "단국대 볼펜 세트 (3입)",  "price":  6_000, "stock": 100},
    "P005": {"name": "단국대 A4 노트 (5권)",    "price":  8_500, "stock": 80},
}

# 인메모리 주문 DB  (Tier 1 상태 교차 검증용)
#   key   : order_id (str)
#   value : {"product_id", "product_name", "amount", "status", "created_at"}
_order_db: dict[str, dict] = {}
_order_counter: int = 0


# 메인 페이지 (쇼핑몰 UI)
@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(render_demo_page("generic"))


# 상품 조회
@app.get("/products")
async def list_products():
    """상품 목록을 반환합니다."""
    return {"products": PRODUCTS, "total": len(PRODUCTS)}


@app.get("/products/{product_id}")
async def get_product(product_id: str):
    """단일 상품을 조회합니다."""
    if product_id not in PRODUCTS:
        raise HTTPException(status_code=404, detail="상품을 찾을 수 없습니다.")
    return {"product_id": product_id, **PRODUCTS[product_id]}


# 주문 생성 / 조회  (Tier 1 상태 교차 검증 엔드포인트)
@app.post("/orders")
async def create_order(request: Request):
    """
    주문을 생성하고 order_id를 반환합니다.
    HookLens Tier 1: 상태 생성 경로로 사용됩니다.

    요청 예시:
      {"product_id": "P001"}
    """
    global _order_counter

    try:
        data = await request.json()
    except Exception:
        data = {}

    _order_counter += 1
    order_id = str(_order_counter)

    product_id   = data.get("product_id", "P001")
    product_info = PRODUCTS.get(product_id, {"name": "알 수 없는 상품", "price": 0})

    _order_db[order_id] = {
        "order_id":     order_id,
        "product_id":   product_id,
        "product_name": product_info["name"],
        "amount":       product_info["price"],
        "status":       "pending",   # 결제 대기 → 웹훅 수신 후 paid 로 변경
    }

    return {
        "order_id": order_id,
        "status":   "pending",
        "message":  f"주문이 생성되었습니다. (상품: {product_info['name']})",
    }


@app.get("/orders")
async def list_orders():
    """전체 주문 목록을 반환합니다."""
    return {"orders": list(_order_db.values()), "total": len(_order_db)}


@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    """
    주문 상태를 조회합니다.
    HookLens Tier 1: 상태 조회 경로로 사용됩니다.
    """
    if order_id not in _order_db:
        raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다.")
    return _order_db[order_id]


# 모의 HMAC 웹훅 수신 엔드포인트
# [의도된 취약점 — HookLens 탐지 대상]
#   WHSEC-002  (HIGH)   : 일반 비교 사용 — 타이밍 노출 가능성(시크릿 복구를 입증한 것은 아님)
#   WHSEC-004  (MEDIUM) : "x-timestamp" 헤더를 읽지만 time.time()과 비교하지 않음 → 만료된 요청 재전송(Replay) 공격 가능
@app.post("/webhook/generic-payment")
async def generic_payment_webhook(
    request: Request,
    x_signature: str = Header(None),
):
    """
    모의 HMAC 결제 완료 웹훅을 수신하고 주문 상태를 업데이트합니다.

    모의 HMAC 웹훅 형식:
      헤더: X-Signature: sha256=<HMAC-SHA256 hex>
      바디: {"eventType": "PAYMENT_STATUS_CHANGED", "data": {...}}
    """
    payload = await request.body()

    # 서명 헤더 존재 여부 확인
    if x_signature is None:
        raise HTTPException(
            status_code=401,
            detail="서명 헤더(X-Signature)가 없습니다.",
        )

    # Content-Type 검증
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        raise HTTPException(status_code=415, detail="Content-Type은 application/json이어야 합니다.")

    # [취약점 WHSEC-004]
    # x-timestamp 헤더를 읽기는 하지만,
    # 현재 시각(time.time())과 비교하지 않아 재전송 공격에 취약합니다.
    # 안전한 코드:
    #   import time
    #   ts = request.headers.get("x-timestamp")
    #   if not ts or abs(time.time() - int(ts)) > 300:
    #       raise HTTPException(401, "요청이 만료되었습니다.")
    timestamp = request.headers.get("x-timestamp")  # 읽기만 하고 검증 안 함

    # 서명 계산 
    # 사용자 정의 HMAC 프로토콜: 실제 결제 제공자와 연동하지 않는 모의 서비스
    expected = "sha256=" + hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()

    # [취약점 WHSEC-002] 
    # == 연산자로 서명을 비교하면 Python이 문자를 앞에서부터 하나씩 비교하다가
    # 불일치하는 즉시 False를 반환합니다.
    # 실제 악용 가능성은 별도 검증이 필요하며, 여기서는 위험한 비교 패턴을 보여줍니다.
    # 안전한 코드:
    #   if not hmac.compare_digest(x_signature, expected):
    #       raise HTTPException(401, "서명이 올바르지 않습니다.")
    if x_signature == expected:          # ← WHSEC-002 취약점
        data = await request.json()

        # 배열로 래핑된 요청(타입 혼동 공격 Stage B)은 400으로 거부
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="잘못된 요청 형식입니다.")

        # 결제 완료 → 주문 상태 업데이트
        order_id = (
            data.get("data", {}).get("orderId")   # 모의 HMAC 표준 형식
            or data.get("order_id")               # HookLens 테스트 형식
        )

        if order_id and str(order_id) in _order_db:
            if (_order_db[str(order_id)].get("source") in {"storefront", "security_demo"}
                    and data.get("amount") != _order_db[str(order_id)]["amount"]):
                raise HTTPException(status_code=400, detail="주문 금액과 결제 알림 금액이 다릅니다.")
            _order_db[str(order_id)]["status"] = "paid"

        event_type = data.get("eventType", "UNKNOWN")
        return {
            "result":     "ok",
            "event_type": event_type,
            "order_id":   order_id,
            "message":    "결제 정보가 처리되었습니다.",
        }

    raise HTTPException(status_code=401, detail="서명 검증에 실패했습니다.")


# 헬스체크
@app.get("/health")
async def health():
    return {
        "status":      "ok",
        "shop":        "단국 굿즈샵",
        "total_orders": len(_order_db),
    }


# 화면과 모의 발신기만 설치하며, 위 웹훅 검증 함수는 그대로 분석할 수 있습니다.
install_demo_ui(app, _order_db, "generic", WEBHOOK_SECRET, "/webhook/generic-payment", products=PRODUCTS)
