"""
demo/shop_server.py

  단국 굿즈샵 — TossPayments 결제 연동 서버 (시연용)

[시연 시나리오]
  이 서버는 단국대 굿즈를 판매하는 온라인 쇼핑몰 개발자가
  토스페이먼츠 결제 웹훅을 연동한 상황을 가정합니다.

  "개발은 다 됐는데... 혹시 보안에 문제가 있지 않을까?"
  → WebhookFilter에 코드를 입력하면 취약점을 자동으로 찾아줍니다.

[WebhookFilter 입력값]
  소스코드         : demo/shop_server.py (이 파일)
  웹훅 URL         : http://localhost:8000
  HMAC 시크릿 키   : dku-toss-secret-2026
  상태 생성 경로   : /orders
  상태 조회 경로   : /orders/{id}

[예상 탐지 결과]
  WHSEC-002  HIGH    - 서명 비교에 == 사용 (타이밍 공격 취약)
  WHSEC-004  MEDIUM  - toss-timestamp 헤더를 받지만 만료 검증 안 함

[실행 방법]
  pip install fastapi uvicorn
  uvicorn demo.shop_server:app --port 8000 --reload
"""

import base64
import hashlib
import hmac

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

# 앱 설정
app = FastAPI(
    title="단국 굿즈샵",
    description="토스페이먼츠 결제 연동 쇼핑몰 (WebhookFilter 시연용)",
    version="1.0.0",
)

# 웹훅 검증용 시크릿 키 (실제 서비스에서는 환경변수로 관리해야 합니다)
WEBHOOK_SECRET = b"dku-toss-secret-2026"

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
    rows = "".join(
        f"<tr><td>{pid}</td><td>{p['name']}</td>"
        f"<td>{p['price']:,}원</td><td>{p['stock']}개</td></tr>"
        for pid, p in PRODUCTS.items()
    )
    return f"""
    <!DOCTYPE html>
    <html lang=\"ko\">
    <head>
      <meta charset=\"UTF-8\">
      <title>단국 굿즈샵</title>
      <style>
        body {{ font-family: 'Malgun Gothic', sans-serif; max-width: 800px;
               margin: 40px auto; padding: 0 20px; color: #333; }}
        h1   {{ color: #003087; border-bottom: 3px solid #003087; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th   {{ background: #003087; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .badge {{ background: #e74c3c; color: white; padding: 3px 8px;
                  border-radius: 4px; font-size: 0.8em; }}
        footer {{ margin-top: 40px; color: #999; font-size: 0.85em; }}
      </style>
    </head>
    <body>
      <h1>🎓 단국 굿즈샵</h1>
      <p>단국대학교 공식 기념품 온라인 스토어입니다.</p>
      <p>결제는 <strong>토스페이먼츠</strong>를 통해 처리됩니다.
         <span class=\"badge\">WebhookFilter 시연용</span></p>

      <h2>📦 상품 목록</h2>
      <table>
        <tr><th>상품 코드</th><th>상품명</th><th>가격</th><th>재고</th></tr>
        {rows}
      </table>

      <h2>🛒 주문 현황</h2>
      <p>현재 주문 수: <strong>{len(_order_db)}건</strong>
         | <a href=\"/orders\">전체 주문 조회 (GET)</a></p>

      <h2>🔌 API 엔드포인트</h2>
      <table>
        <tr><th>Method</th><th>Path</th><th>설명</th></tr>
        <tr><td>GET</td><td>/products</td><td>상품 목록 조회</td></tr>
        <tr><td>POST</td><td>/orders</td><td>주문 생성</td></tr>
        <tr><td>GET</td><td>/orders/{{id}}</td><td>주문 상태 조회</td></tr>
        <tr><td>POST</td><td>/webhook/toss-payment</td><td>TossPayments 웹훅 수신</td></tr>
      </table>

      <footer>
        ⚠️ 이 서버는 WebhookFilter 캡스톤 시연용 데모 서버입니다.
        실제 서비스에 사용하지 마세요.
      </footer>
    </body>
    </html>
    """


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
    WebhookFilter Tier 1: 상태 생성 경로로 사용됩니다.

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
    WebhookFilter Tier 1: 상태 조회 경로로 사용됩니다.
    """
    if order_id not in _order_db:
        raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다.")
    return _order_db[order_id]


# TossPayments 웹훅 수신 엔드포인트
#
# [의도된 취약점 — WebhookFilter 탐지 대상]
#
#   WHSEC-002  (HIGH)   : 서명 비교에 == 연산자 사용
#                         → 타이밍 공격으로 시크릿 키 추측 가능
#
#   WHSEC-004  (MEDIUM) : "toss-timestamp" 헤더를 읽지만
#                         time.time()과 비교하지 않음
#                         → 만료된 요청 재전송(Replay) 공격 가능
@app.post("/webhook/toss-payment")
async def toss_payment_webhook(
    request: Request,
    tosspayments_webhook_signature: str = Header(None),
):
    """
    토스페이먼츠 결제 완료 웹훅을 수신하고 주문 상태를 업데이트합니다.

    토스페이먼츠 웹훅 형식:
      헤더: TossPayments-Webhook-Signature: <Base64(HMAC-SHA256(secret, body))>
      바디: {"eventType": "PAYMENT_STATUS_CHANGED", "data": {...}}
    """
    payload = await request.body()

    # 서명 헤더 존재 여부 확인
    if tosspayments_webhook_signature is None:
        raise HTTPException(
            status_code=401,
            detail="서명 헤더(TossPayments-Webhook-Signature)가 없습니다.",
        )

    # Content-Type 검증
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        raise HTTPException(status_code=415, detail="Content-Type은 application/json이어야 합니다.")

    # [취약점 WHSEC-004]
    # toss-timestamp 헤더를 읽기는 하지만,
    # 현재 시각(time.time())과 비교하지 않아 재전송 공격에 취약합니다.
    #
    # 안전한 코드:
    #   import time
    #   ts = request.headers.get("toss-timestamp")
    #   if not ts or abs(time.time() - int(ts)) > 300:
    #       raise HTTPException(401, "요청이 만료되었습니다.")
    timestamp = request.headers.get("toss-timestamp")  # 읽기만 하고 검증 안 함

    # 서명 계산 
    # 토스페이먼츠: HMAC-SHA256 결과를 Base64 인코딩
    sig_bytes = hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).digest()
    expected  = base64.b64encode(sig_bytes).decode()

    # [취약점 WHSEC-002] 
    # == 연산자로 서명을 비교하면 Python이 문자를 앞에서부터 하나씩 비교하다가
    # 불일치하는 즉시 False를 반환합니다.
    # 공격자는 응답 시간 차이를 측정해 올바른 서명을 추측할 수 있습니다.
    #
    # 안전한 코드:
    #   if not hmac.compare_digest(tosspayments_webhook_signature, expected):
    #       raise HTTPException(401, "서명이 올바르지 않습니다.")
    if tosspayments_webhook_signature == expected:          # ← WHSEC-002 취약점
        data = await request.json()

        # 배열로 래핑된 요청(타입 혼동 공격 Stage B)은 400으로 거부
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="잘못된 요청 형식입니다.")

        # 결제 완료 → 주문 상태 업데이트
        order_id = (
            data.get("data", {}).get("orderId")   # 토스페이먼츠 표준 형식
            or data.get("order_id")               # WebhookFilter 테스트 형식
        )

        if order_id and str(order_id) in _order_db:
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