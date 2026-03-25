"""
samples/vulnerable_webhook.py — SAST/DAST 탐지 대상 취약 서버

[역할]
  SAST 규칙 검증과 DAST 공격 테스트를 위한 의도적 취약 웹훅 서버.
  아래 5가지 취약점이 각 엔드포인트에 명시적으로 포함되어 있다.

[취약점 목록]
  [V1] 서명 검증 누락       → POST /webhook/no-verify
       - 서명 헤더를 전혀 읽지 않고 바로 DB 상태 변경
       - 위조 요청을 보내도 수락 → Tier 1 상태 변화 감지 가능

  [V2] 타이밍 공격 (== 비교) → POST /webhook/timing-attack
       - hmac.compare_digest 대신 == 로 서명 비교
       - 공격자가 응답 시간 차이로 서명 바이트를 역추론 가능

  [V3a] 취약한 해시 — SHA1  → POST /webhook/weak-hash-sha1
        - SHA1 은 충돌 공격에 취약 (NIST 권고: SHA256 이상 사용)

  [V3b] 취약한 해시 — MD5   → POST /webhook/weak-hash-md5
        - MD5 는 SHA1 보다 더 취약 (충돌 공격 실용화됨)

  [V4] 타임스탬프 검증 없음  → POST /webhook/no-timestamp
       - 유효한 서명이면 오래된 요청도 수락 → 재전송 공격 가능

  [V5-a] 내부 위임 결함      → POST /webhook/delegated
         - 같은 파일 내 _verify_delegated() 함수를 호출하는데
           해당 함수 내부에서 == 비교 사용 → SAST import 추적으로 탐지

  [V5-b] 외부 파일 위임 결함 → POST /webhook/delegated-external
         - utils_vulnerable.verify_signature() 를 import하여 사용하는데
           해당 함수 내부에서 == 비교 사용 → SAST import 추적으로 탐지

[Tier 1 상태 교차 검증]
  서명 위조 요청 수락 시 _order_db[order_id] 상태가 변경됨.
  Probe가 공격 전후 GET /orders/{order_id} 를 비교하면 변화를 감지할 수 있음.
"""

# TODO: FastAPI 앱 인스턴스 생성
# TODO: utils_vulnerable 에서 결함 있는 verify_signature import
# TODO: SECRET, _order_db 전역 변수 정의
# TODO: 각 취약 엔드포인트 구현
#   - /webhook/no-verify      : 서명 검증 없이 바로 _order_db 상태 변경
#   - /webhook/timing-attack  : == 로 서명 비교 후 상태 변경
#   - /webhook/weak-hash-sha1 : hmac.new(SECRET, payload, sha1) 으로 서명 생성/검증
#   - /webhook/weak-hash-md5  : hmac.new(SECRET, payload, md5) 로 서명 생성/검증
#   - /webhook/no-timestamp   : 타임스탬프 헤더 읽지 않음, sha256 서명만 검증
#   - /webhook/delegated      : _verify_delegated() 내부 함수 위임 (== 비교)
#   - /webhook/delegated-external : external_verify() 외부 함수 위임
# TODO: _verify_delegated() 내부 함수 구현 (== 비교 — V5-a)
# TODO: GET /orders/{order_id} 엔드포인트 구현 (Tier 1 상태 조회)
# TODO: POST /orders 엔드포인트 구현 (Tier 1 상태 생성)
