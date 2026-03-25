"""
samples/utils_vulnerable.py — SAST 규칙 5 (외부 파일 import 추적) 테스트용

[역할]
  vulnerable_webhook.py 에서 import하여 사용하는 외부 검증 함수.
  함수 시그니처만 보면 정상적인 서명 검증 함수처럼 보이지만,
  내부 구현에 타이밍 공격 취약점(== 비교)이 숨겨져 있다.

  SAST 엔진이 단순히 호출 여부만 확인하면 탐지 불가.
  engine.resolve_import() 로 import를 추적하여 함수 본문까지 분석해야만 탐지 가능.

[포함할 함수]
  verify_signature(signature, payload, secret) → bool
    - 겉보기에는 일반적인 서명 검증 함수
    - 내부에서 hmac.compare_digest 대신 == 사용 → [V2] 타이밍 공격 취약

[SAST 탐지 포인트]
  WHSEC-002: == 비교
  WHSEC-005: vulnerable_webhook.py 에서 이 함수를 import하여 사용 → 위임 결함
"""

# TODO: verify_signature(signature, payload, secret) 함수 구현
#   - hmac.new(secret, payload, hashlib.sha256).hexdigest() 로 서명 계산
#   - 의도적으로 == 로 비교 (취약점 삽입)
#   - 주석으로 취약점 명시 (교육 목적)
