"""
samples/secure_webhook.py — SAST 통과 기준 안전 서버

[역할]
  모든 SAST 규칙을 통과하는 올바른 웹훅 핸들러 구현 예시.
  DAST 공격에도 취약하지 않아야 한다.

[충족해야 하는 보안 요건]
  [S1] 모든 핸들러에 서명 검증 존재
       - 서명 헤더가 없으면 401 반환

  [S2] 상수 시간 비교 (hmac.compare_digest 사용)
       - == 대신 hmac.compare_digest 로 타이밍 공격 방지

  [S3] SHA256 이상의 해시 알고리즘 사용
       - sha256= 접두사 + hashlib.sha256

  [S4] 타임스탬프 검증 (5분 이내)
       - X-Timestamp 헤더 읽기
       - abs(time.time() - ts) <= TIMESTAMP_TOLERANCE_SECONDS

  [S5] 외부 위임 함수도 내부적으로 안전하게 구현
       - 외부 함수를 사용하지 않거나, 사용하더라도 안전한 구현체만 사용

[Tier 1 상태 교차 검증]
  유효한 서명일 때만 _order_db 상태가 변경됨.
  위조 서명 요청 → 401 반환 → DB 상태 불변.
  공격 전후 GET /orders/{order_id} 비교 → 변화 없음 확인.

[시크릿 키 관리]
  환경 변수(WEBHOOK_SECRET)에서 읽고, 없으면 기본값 사용.
  하드코딩 방식(b"...") 대신 os.environ.get() 사용 → WHSEC-006 오탐 방지.

[내부 헬퍼 함수]
  _compute_signature(payload) → str  : sha256= 접두사 포함 서명 생성
  _verify_signature(header_sig, payload) → bool : compare_digest 로 검증
  _verify_timestamp(timestamp_str) → bool : 5분 이내 여부 확인
"""

# TODO: FastAPI 앱 인스턴스 생성
# TODO: SECRET 환경 변수에서 읽기 (os.environ.get("WEBHOOK_SECRET") or "supersecretkey")
# TODO: TIMESTAMP_TOLERANCE_SECONDS = 300 상수 정의
# TODO: _order_db 전역 변수 정의
# TODO: _compute_signature() 헬퍼 구현 (sha256= 접두사 포함)
# TODO: _verify_signature() 헬퍼 구현 (hmac.compare_digest 사용)
# TODO: _verify_timestamp() 헬퍼 구현 (abs(time.time() - ts) <= tolerance)
# TODO: /webhook/secure 엔드포인트 구현
#   - 서명 헤더 없으면 401
#   - 타임스탬프 헤더 없으면 401
#   - _verify_signature() 실패 시 401
#   - _verify_timestamp() 실패 시 401
#   - 검증 통과 시 _order_db 상태 변경 후 200 반환
# TODO: GET /orders/{order_id} 엔드포인트 구현 (Tier 1 상태 조회)
# TODO: POST /orders 엔드포인트 구현 (Tier 1 상태 생성)
