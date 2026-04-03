"""
server/test_server.py

stdlib http.server 기반 테스트 서버
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

취약 엔드포인트 (vulnerable_webhook.py 대응):
  POST /webhook/no-verify          [V1] 서명 없음
  POST /webhook/timing-attack      [V2] == 비교
  POST /webhook/weak-hash-sha1     [V3a] SHA1
  POST /webhook/weak-hash-md5      [V3b] MD5
  POST /webhook/no-timestamp       [V4] 타임스탬프 미검증

안전 엔드포인트 (secure_webhook.py 대응):
  POST /webhook/secure             전부 안전 (sha256 + compare_digest + timestamp)

플랫폼별 취약 엔드포인트:
  POST /webhook/stripe             [Stripe]       타임스탬프 미검증 (t=,v1= 형식)
  POST /webhook/toss               [토스페이먼츠]  == 비교 타이밍 공격 (Base64 HMAC)
  POST /webhook/slack              [Slack]        타임스탬프 미검증 (v0= 형식)
  POST /webhook/portone            [PortOne V2]   서명 검증 누락 (헤더 존재만 확인)

상태 조회 (Tier 1 상태 교차 검증):
  POST /orders                     주문 생성
  GET  /orders/{id}                주문 조회
"""
import hashlib
import hmac
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

SECRET = b"supersecretkey"
TIMESTAMP_TOLERANCE = 300

_order_db: dict = {}
_db_lock = threading.Lock()


def _sig256(payload): return "sha256=" + hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
def _sig1(payload): return "sha1=" + hmac.new(SECRET, payload, hashlib.sha1).hexdigest()
def _sigmd5(payload): return "md5=" + hmac.new(SECRET, payload, hashlib.md5).hexdigest()

# ── 플랫폼별 서명 헬퍼 ───────────────────────────────────────────────
import base64

def _sig_stripe(ts: str, payload: bytes) -> str:
    """Stripe: t=<ts>,v1=HMAC(secret, ts.payload)"""
    signed = f"{ts}.".encode() + payload
    v1 = hmac.new(SECRET, signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={v1}"

def _sig_toss(payload: bytes) -> str:
    """토스페이먼츠: Base64(HMAC-SHA256(secret, payload))"""
    return base64.b64encode(
        hmac.new(SECRET, payload, hashlib.sha256).digest()
    ).decode()

def _sig_slack(ts: str, payload: bytes) -> str:
    """Slack: v0=HMAC(secret, 'v0:<ts>:<body>')"""
    base = f"v0:{ts}:".encode() + payload
    return "v0=" + hmac.new(SECRET, base, hashlib.sha256).hexdigest()

def _sig_portone(payload: bytes) -> str:
    """PortOne V2: HMAC-SHA256(secret, payload) hex"""
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def _json(self, code, data):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _update_db(self, data):
        # 배열이면 첫 번째 원소 추출 (Stage B 배열 래핑 처리)
        if isinstance(data, list):
            if not data or not isinstance(data[0], dict):
                return
            data = data[0]
        if not isinstance(data, dict):
            return
        oid = data.get("order_id", "unknown")
        with _db_lock:
            _order_db[oid] = data.get("status", "paid")

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()
        m = {
            "/webhook/no-verify": self._v1,
            "/webhook/timing-attack": self._v2,
            "/webhook/weak-hash-sha1": self._v3a,
            "/webhook/weak-hash-md5": self._v3b,
            "/webhook/no-timestamp": self._v4,
            "/webhook/secure": self._safe,
            # ── 플랫폼별 취약 엔드포인트 ──
            "/webhook/stripe": self._stripe,
            "/webhook/toss": self._toss,
            "/webhook/slack": self._slack,
            "/webhook/portone": self._portone,
            "/orders": self._create_order,
        }
        h = m.get(path)
        if h:
            h(body)
        else:
            self._json(404, {"error": "Not found"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/orders/"):
            oid = path.split("/orders/")[1]
            with _db_lock:
                if oid in _order_db:
                    self._json(200, {"order_id": oid, "status": _order_db[oid]})
                else:
                    self._json(404, {"detail": "Not found"})
        else:
            self._json(404, {"error": "Not found"})

    # ── [V1] 서명 없음 ──
    def _v1(self, body):
        try: data = json.loads(body)
        except: data = {}
        self._update_db(data)
        self._json(200, {"status": "ok", "received": data})

    # ── [V2] == 비교 ──
    def _v2(self, body):
        sig = self.headers.get("X-Hub-Signature-256")
        if not sig:
            return self._json(401, {"detail": "Missing signature"})
        if sig == _sig256(body):  # 취약: ==
            try: data = json.loads(body)
            except: data = {}
            self._update_db(data)
            return self._json(200, {"status": "ok"})
        self._json(401, {"detail": "Invalid signature"})

    # ── [V3a] SHA1 ──
    def _v3a(self, body):
        sig = self.headers.get("X-Hub-Signature")
        if not sig:
            return self._json(401, {"detail": "Missing signature"})
        if hmac.compare_digest(sig, _sig1(body)):
            try: data = json.loads(body)
            except: data = {}
            self._update_db(data)
            return self._json(200, {"status": "ok"})
        self._json(401, {"detail": "Invalid signature"})

    # ── [V3b] MD5 ──
    def _v3b(self, body):
        sig = self.headers.get("X-Signature")
        if not sig:
            return self._json(401, {"detail": "Missing signature"})
        if hmac.compare_digest(sig, _sigmd5(body)):
            try: data = json.loads(body)
            except: data = {}
            self._update_db(data)
            return self._json(200, {"status": "ok"})
        self._json(401, {"detail": "Invalid signature"})

    # ── [V4] 타임스탬프 미검증 ──
    def _v4(self, body):
        sig = self.headers.get("X-Hub-Signature-256")
        if not sig:
            return self._json(401, {"detail": "Missing signature"})
        if not hmac.compare_digest(sig, _sig256(body)):
            return self._json(401, {"detail": "Invalid signature"})
        try: data = json.loads(body)
        except: data = {}
        self._update_db(data)
        self._json(200, {"status": "ok"})

    # ── [S] 안전 ──
    def _safe(self, body):
        # Content-Type 검증 (타입 혼동 방어)
        ct = self.headers.get("Content-Type", "")
        if "application/json" not in ct:
            return self._json(415, {"detail": "Unsupported Media Type"})

        sig = self.headers.get("X-Hub-Signature-256")
        ts = self.headers.get("X-Timestamp")
        if not sig:
            return self._json(401, {"detail": "Missing signature"})
        if not ts:
            return self._json(401, {"detail": "Missing timestamp"})
        try:
            if abs(time.time() - int(ts)) > TIMESTAMP_TOLERANCE:
                return self._json(401, {"detail": "Timestamp expired"})
        except (ValueError, TypeError):
            return self._json(401, {"detail": "Invalid timestamp"})
        if not hmac.compare_digest(sig, _sig256(body)):
            return self._json(401, {"detail": "Invalid signature"})

        try: data = json.loads(body)
        except:
            return self._json(400, {"detail": "Invalid JSON"})
        # 배열 거부
        if isinstance(data, list):
            return self._json(400, {"detail": "Expected object, got array"})
        # 의심스러운 키 거부 (프로토타입 오염 방어)
        SUSPICIOUS_KEYS = {"__proto__", "constructor", "prototype"}
        if SUSPICIOUS_KEYS & set(data.keys()):
            return self._json(400, {"detail": "Suspicious keys rejected"})
        self._update_db(data)
        self._json(200, {"status": "ok", "received": data})

    # ── [Stripe] 취약: 타임스탬프 미검증 ──
    # 실제 Stripe 서명 형식(t=<ts>,v1=<sig>)을 검증하되
    # 타임스탬프 유효기간 체크 없음 → 재전송 공격에 취약
    def _stripe(self, body):
        sig_header = self.headers.get("Stripe-Signature", "")
        if not sig_header:
            return self._json(401, {"detail": "Missing Stripe-Signature"})
        # t=, v1= 파싱
        try:
            parts = dict(item.split("=", 1) for item in sig_header.split(","))
            ts = parts.get("t", "")
            v1 = parts.get("v1", "")
        except Exception:
            return self._json(401, {"detail": "Invalid signature format"})
        if not ts or not v1:
            return self._json(401, {"detail": "Missing t or v1"})
        # 서명 검증 (타임스탬프 유효기간 체크 없음 → 취약)
        expected = _sig_stripe(ts, body)
        expected_v1 = expected.split("v1=")[1]
        if not hmac.compare_digest(v1, expected_v1):
            return self._json(401, {"detail": "Invalid signature"})
        try: data = json.loads(body)
        except: data = {}
        self._update_db(data)
        self._json(200, {"status": "ok"})

    # ── [토스페이먼츠] 취약: == 비교 (타이밍 공격) ──
    # Base64 HMAC-SHA256 형식을 검증하되
    # hmac.compare_digest 대신 == 비교 → 타이밍 공격에 취약
    def _toss(self, body):
        sig = self.headers.get("TossPayments-Webhook-Signature", "")
        if not sig:
            return self._json(401, {"detail": "Missing TossPayments-Webhook-Signature"})
        expected = _sig_toss(body)
        if sig == expected:  # 취약: == 비교
            try: data = json.loads(body)
            except: data = {}
            self._update_db(data)
            return self._json(200, {"status": "ok"})
        self._json(401, {"detail": "Invalid signature"})

    # ── [Slack] 취약: 타임스탬프 미검증 ──
    # v0=HMAC(secret, v0:<ts>:<body>) 형식을 검증하되
    # 타임스탬프 유효기간 체크 없음 → 재전송 공격에 취약
    def _slack(self, body):
        sig = self.headers.get("X-Slack-Signature", "")
        ts = self.headers.get("X-Slack-Request-Timestamp", "")
        if not sig:
            return self._json(401, {"detail": "Missing X-Slack-Signature"})
        if not ts:
            return self._json(401, {"detail": "Missing X-Slack-Request-Timestamp"})
        # 서명 검증 (타임스탬프 유효기간 체크 없음 → 취약)
        expected = _sig_slack(ts, body)
        if not hmac.compare_digest(sig, expected):
            return self._json(401, {"detail": "Invalid signature"})
        try: data = json.loads(body)
        except: data = {}
        self._update_db(data)
        self._json(200, {"status": "ok"})

    # ── [PortOne V2] 취약: 서명 검증 누락 ──
    # webhook-signature 헤더가 있어도 실제 검증 로직 없음
    # → 어떤 서명이든 수락
    def _portone(self, body):
        # 헤더 존재 여부만 확인하고 실제 검증 안 함 (취약)
        sig = self.headers.get("webhook-signature", "")
        if not sig:
            return self._json(401, {"detail": "Missing webhook-signature"})
        # 검증 없이 바로 처리 → WHSEC-001 유형 취약점
        try: data = json.loads(body)
        except: data = {}
        self._update_db(data)
        self._json(200, {"status": "ok"})

    # ── 주문 ──
    def _create_order(self, body):
        with _db_lock:
            oid = str(len(_order_db) + 1)
            _order_db[oid] = "pending"
        self._json(200, {"order_id": oid, "status": "pending"})


def start_server(port=9000):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def reset_db():
    with _db_lock:
        _order_db.clear()


if __name__ == "__main__":
    p = 9000
    print(f"서버 시작: http://127.0.0.1:{p}")
    srv = HTTPServer(("127.0.0.1", p), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
