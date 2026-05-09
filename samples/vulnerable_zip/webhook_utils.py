"""
webhook_utils.py — 단국 굿즈샵 웹훅 감사 로깅 유틸리티

개발자가 서명 검증 결과를 로그로 남기기 위해 작성한 공통 유틸리티입니다.
shop_server.py 에서 import 하여 사용합니다.

[⚠️ WHSEC-005 취약점]
  audit_signature() 내부에서 서명을 == 로 비교합니다.
  타이밍 공격에 노출될 수 있습니다.
"""

import hashlib
import hmac
import logging

logger = logging.getLogger("단국굿즈샵.audit")


def audit_signature(received_sig: str, payload: bytes, secret: bytes) -> bool:
    """
    서명을 검증하고 감사 로그를 남깁니다.
    shop_server.py의 /webhook/toss-payment 핸들러에서 호출됩니다.

    ⚠️ [WHSEC-005] : == 비교 사용 → 타이밍 공격 가능
    ✅ 안전한 코드 : hmac.compare_digest(received_sig, computed) 사용
    """
    computed = hmac.new(secret, payload, hashlib.sha256).hexdigest()

    # 취약점: 상수 시간 비교 미사용
    if received_sig == computed:       # ← WHSEC-005 탐지 대상
        logger.info("[AUDIT] 서명 검증 통과 — 정상 요청")
        return True

    logger.warning("[AUDIT] 서명 검증 실패 — 위조 요청 의심")
    return False