"""
utils_vulnerable.py

SAST 규칙 5 — 외부 파일 import 추적 테스트용.
이 파일의 verify_signature() 는 == 비교를 사용하는 결함이 있습니다.
vulnerable_webhook.py 에서 import 해서 사용합니다.
"""

import hashlib
import hmac


def verify_signature(signature: str, payload: bytes, secret: bytes) -> bool:
    """
    [결함] 타이밍 공격에 취약한 == 비교.
    호출하는 쪽 코드만 보면 문제가 없어 보이지만,
    이 함수 내부에 결함이 있어 SAST가 import 추적으로만 탐지 가능.
    """
    computed = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return signature == computed  # [V2] 타이밍 공격 취약점
