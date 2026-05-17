"""
shop_server.py — 단국 굿즈샵 (취약한 버전)

  WebhookFilter 시연용 — 취약한 서버 (WHSEC 001 ~ 005 전부 포함)


[WebhookFilter 입력값]
  소스코드         : vulnerable_zip.zip (이 파일 + webhook_utils.py)
  웹훅 URL         : http://localhost:8000
  HMAC 시크릿 키   : dku-toss-secret-2026
  상태 생성 경로   : /orders
  상태 조회 경로   : /orders/{id}

[예상 탐지 결과]
  /webhook/toss-payment
    WHSEC-002  HIGH      서명 비교에 == 사용 (타이밍 공격)
    WHSEC-003  MEDIUM    SHA1 취약 해시 알고리즘 사용
    WHSEC-004  MEDIUM    toss-timestamp 수신하나 만료 미검증
    WHSEC-005  MEDIUM    audit_signature()에서 == 비교 (외부 파일)

  /webhook/toss-event
    WHSEC-001  CRITICAL  서명 검증 로직 완전 누락

[실행 방법]
  uvicorn samples.shop_server:app --port 8000
"""

import hashlib
import hmac

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

# WHSEC-005 트리거: 외부 파일에서 audit_signature import
from webhook_utils import audit_signature

app = FastAPI(
    title="단국 굿즈샵 (취약한 버전)",
    description="WebhookFilter 시연용 — WHSEC 001~005 모두 포함",
)

WEBHOOK_SECRET = b"dku-toss-secret-2026"

# 상품 목록
PRODUCTS = {
    "P001": {"name": "단국대 후드티 (네이비)",  "price": 45_000, "stock": 30},
    "P002": {"name": "단국대 스텐 텀블러",      "price": 28_000, "stock": 50},
    "P003": {"name": "단국대 캔버스 토트백",    "price": 18_000, "stock": 40},
    "P004": {"name": "단국대 볼펜 세트 (3입)",  "price":  6_000, "stock": 100},
    "P005": {"name": "단국대 A4 노트 (5권)",    "price":  8_500, "stock": 80},
}

# 인메모리 주문 DB
_order_db: dict[str, dict] = {}
_order_counter: int = 0


# UI / 상품 / 주문
@app.get("/", response_class=HTMLResponse)
async def index():
    rows = "".join(
        f"<tr><td>{pid}</td><td>{p['name']}</td>"
        f"<td>{p['price']:,}원</td><td>{p['stock']}개</td></tr>"
        for pid, p in PRODUCTS.items()
    )
    return f"""
    <!DOCTYPE html><html lang="ko">
    <head><meta charset="UTF-8"><title>단국 굿즈샵 (취약)</title>
    <style>
      body{{font-family:'Malgun Gothic',sans-serif;max-width:800px;
           margin:40px auto;padding:0 20px;color:#333}}
      h1{{color:#c0392b;border-bottom:3px solid #c0392b;padding-bottom:8px}}
      table{{width:100%;border-collapse:collapse;margin-top:20px}}
      th,td{{border:1px solid #ddd;padding:10px;text-align:left}}
      th{{background:#c0392b;color:white}}
      tr:nth-child(even){{background:#fff5f5}}
      .badge{{background:#e74c3c;color:white;padding:3px 8px;
              border-radius:4px;font-size:.8em}}
    </style></head>
    <body>
      <h1>🎓 단국 굿즈샵 <span class="badge">⚠️ 취약한 버전</span></h1>
      <p>WHSEC 001 ~ 005 전체 취약점이 포함된 시연용 서버입니다.</p>
      <table>
        <tr><th>코드</th><th>상품명</th><th>가격</th><th>재고</th></tr>
        {rows}
      </table>
      <p>주문 수: <strong>{len(_order_db)}건</strong>
         | <a href="/orders">주문 목록</a></p>
    </body></html>
    """


@app.get("/products")
async def list_products():
    return {"products": PRODUCTS}


@app.post("/orders")
async def create_order(request: Request):
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
        "status":       "pending",
    }
    return {"order_id": order_id, "status": "pending"}


@app.get("/orders")
async def list_orders():
    return {"orders": list(_order_db.values()), "total": len(_order_db)}


@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    if order_id not in _order_db:
        raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다.")
    return _order_db[order_id]


# [취약 핸들러 1] 결제 완료 웹훅
# WHSEC-002 (HIGH)   : signature == expected  (== 비교)
# WHSEC-003 (MEDIUM) : hmac.new(..., hashlib.sha1)  (취약 해시)
# WHSEC-004 (MEDIUM) : "toss-timestamp" 읽지만 time.time() 없음
# WHSEC-005 (MEDIUM) : audit_signature() 내부에서 == 비교 (외부 파일)

@app.post("/webhook/toss-payment")
async def toss_payment_webhook(
    request: Request,
    tosspayments_webhook_signature: str = Header(None),
):
    """토스페이먼츠 결제 완료 웹훅 수신"""
    payload = await request.body()
    
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        raise HTTPException(415)

    if tosspayments_webhook_signature is None:
        raise HTTPException(status_code=401, detail="서명 헤더가 없습니다.")

    # [WHSEC-004] toss-timestamp 수신, 만료 검증 없음
    # 안전한 코드: abs(time.time() - int(timestamp)) <= 300
    timestamp = request.headers.get("toss-timestamp")

    # [WHSEC-003] SHA1 취약 해시 알고리즘 사용 
    # 안전한 코드: hashlib.sha256
    expected = hmac.new(WEBHOOK_SECRET, payload, hashlib.sha1).hexdigest()

    # [WHSEC-002] == 비교 → 타이밍 공격 취약
    # 안전한 코드: hmac.compare_digest(tosspayments_webhook_signature, expected)
    if tosspayments_webhook_signature == expected:

        # [WHSEC-005] 외부 파일 위임 함수 내 == 비교
        audit_signature(tosspayments_webhook_signature, payload, WEBHOOK_SECRET)

        if not isinstance(payload, bytes):
            raise HTTPException(status_code=400, detail="잘못된 요청입니다.")

        data = await request.json()
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="잘못된 요청 형식입니다.")

        order_id = (
            data.get("data", {}).get("orderId")
            or data.get("order_id")
        )
        if order_id and str(order_id) in _order_db:
            _order_db[str(order_id)]["status"] = "paid"

        return {"result": "ok", "message": "결제 처리 완료"}

    raise HTTPException(status_code=401, detail="서명 검증 실패")


# [취약 핸들러 2] 이벤트 알림 웹훅
# WHSEC-001 (CRITICAL) : 서명 검증 로직 완전 누락
@app.post("/webhook/toss-event")
async def toss_event_webhook(request: Request):
    """
    토스페이먼츠 이벤트 알림 웹훅 수신

    [WHSEC-001] : 서명 검증 로직이 없습니다.
    누구든지 이 엔드포인트로 요청을 보내면 처리됩니다.
    안전한 코드: hmac.compare_digest로 서명 검증 후 처리
    """
    try:
        data = await request.json()
    except Exception:
        data = {}

    event_type = data.get("eventType", "UNKNOWN")
    return {
        "result":     "ok",
        "event_type": event_type,
        "message":    "이벤트가 처리되었습니다.",
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": "취약한 버전", "orders": len(_order_db)}
