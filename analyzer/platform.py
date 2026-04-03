"""
analyzer/platform.py  (v2 — Step 1 고도화)

플랫폼 감지 모듈 — 소스 코드에서 웹훅 서명 플랫폼을 자동 판별
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

v2 변경 사항:
  TOSS_PAYMENTS  — tosspayments-webhook-signature 헤더
  SLACK          — X-Slack-Signature 헤더 (v0=sha256_sig 형식)
  PORTONE_V2     — webhook-signature 헤더 (Standard Webhooks 준수)
  기존: GITHUB, STRIPE, GENERIC, UNKNOWN 유지
"""

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List

from analyzer.engine import ParseResult, WebhookHandler


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 데이터 구조
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Platform(Enum):
    GITHUB        = "GitHub"
    STRIPE        = "Stripe"
    TOSS_PAYMENTS = "토스페이먼츠"
    SLACK         = "Slack"
    PORTONE_V2    = "PortOne V2"
    GENERIC       = "Generic"
    UNKNOWN       = "Unknown"


@dataclass
class SignatureFormat:
    platform: Platform
    sig_header: str
    prefix: str               # HMAC 결과 앞에 붙는 접두사 (e.g. "sha256=")
    algo: str                 # hashlib 알고리즘명 (e.g. "sha256")
    is_stripe: bool = False   # True = t=<ts>,v1=<sig> 조립 필요
    is_slack: bool = False    # True = v0=<ts>:<body> 조립 필요
    predicted_tier_hint: str = ""


@dataclass
class PlatformDetectionResult:
    filepath: str
    platform: Platform
    sig_format: SignatureFormat
    confidence: str           # "high" / "medium" / "low"
    evidence: List[str] = field(default_factory=list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 헤더 변수명 → 플랫폼 매핑  (Python snake_case 파라미터명)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_GITHUB_HEADERS = {
    "x_hub_signature_256",
    "x_hub_signature",
}
_STRIPE_HEADERS = {
    "stripe_signature",
    "stripe_sig",
}
_TOSS_HEADERS = {
    "tosspayments_webhook_signature",
    "toss_webhook_signature",
    "toss_payments_webhook_signature",
    # HTTP 헤더 → snake_case 변환 형태
    # tosspayments-webhook-signature → tosspayments_webhook_signature
}
_SLACK_HEADERS = {
    "x_slack_signature",
    "x_slack_request_timestamp",
}
_PORTONE_HEADERS = {
    "webhook_signature",
    "portone_signature",
}
_GENERIC_HEADERS = {
    "x_signature",
    "x_webhook_signature",
    "x_secret",
    # 버그 11 수정: "webhook_signature"는 _PORTONE_HEADERS와 중복 → 제거
    # PortOne 검사가 Generic보다 먼저 수행되므로, 중복 시 일반 핸들러가 PortOne으로 오탐됨
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 소스 문자열 패턴 (대소문자 무관)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_TOSS_PATTERNS = [
    r"tosspayments[\-_]webhook[\-_]signature",
    r"TossPayments",
    r"toss_secret",
    r"TOSS_SECRET",
]
_STRIPE_PATTERNS = [
    r"t=.*v1=",
    r"stripe[\._\-]signature",
    r"Stripe-Signature",
    r"stripe\.Webhook",
]
_GITHUB_PATTERNS = [
    # 버그 12 수정: r"sha256=" 제거 — GitHub과 무관한 코드에도 광범위하게 등장하여 오탐 위험
    # (일반 HMAC 코드, 토스페이먼츠, WHSEC-003 수정 스니펫 등에도 포함됨)
    r"X-Hub-Signature-256",
    r"x_hub_signature_256",
    r"github.*webhook",
]
_SLACK_PATTERNS = [
    r"X-Slack-Signature",
    r"x_slack_signature",
    r"v0=",
    r"slack_signing_secret",
]
_PORTONE_PATTERNS = [
    r"webhook[\-_]signature",
    r"portone",
    r"PortOne",
    r"Standard[\s_]Webhooks",
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 플랫폼별 기본 SignatureFormat
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_DEFAULT_FORMATS = {
    Platform.GITHUB: SignatureFormat(
        platform=Platform.GITHUB,
        sig_header="X-Hub-Signature-256",
        prefix="sha256=",
        algo="sha256",
        predicted_tier_hint="Tier 2 예상 — GitHub은 상태 조회 엔드포인트 없음",
    ),
    Platform.STRIPE: SignatureFormat(
        platform=Platform.STRIPE,
        sig_header="Stripe-Signature",
        prefix="",
        algo="sha256",
        is_stripe=True,
        predicted_tier_hint="Tier 1 가능 — 결제/주문 플랫폼, 상태 조회 구현 가능성 높음",
    ),
    Platform.TOSS_PAYMENTS: SignatureFormat(
        platform=Platform.TOSS_PAYMENTS,
        sig_header="TossPayments-Webhook-Signature",
        prefix="",
        algo="sha256",
        predicted_tier_hint="Tier 1 가능 — 국내 결제 플랫폼, 주문 상태 조회 가능성 높음",
    ),
    Platform.SLACK: SignatureFormat(
        platform=Platform.SLACK,
        sig_header="X-Slack-Signature",
        prefix="v0=",
        algo="sha256",
        is_slack=True,
        predicted_tier_hint="Tier 2 예상 — Slack은 메시지 알림 중심, 상태 조회 어려움",
    ),
    Platform.PORTONE_V2: SignatureFormat(
        platform=Platform.PORTONE_V2,
        sig_header="webhook-signature",
        prefix="",
        algo="sha256",
        predicted_tier_hint="Tier 1 가능 — 결제 플랫폼, 상태 조회 가능성 높음",
    ),
    Platform.GENERIC: SignatureFormat(
        platform=Platform.GENERIC,
        sig_header="X-Hub-Signature-256",
        prefix="sha256=",
        algo="sha256",
        predicted_tier_hint="Tier 미확정 — DAST Probe가 런타임에서 결정",
    ),
    Platform.UNKNOWN: SignatureFormat(
        platform=Platform.UNKNOWN,
        sig_header="X-Hub-Signature-256",
        prefix="sha256=",
        algo="sha256",
        predicted_tier_hint="Tier 미확정 — 플랫폼 감지 실패, 수동 확인 필요",
    ),
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 플랫폼 공식 문서 링크
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PLATFORM_DOC_LINKS = {
    Platform.GITHUB: {
        "title": "GitHub Webhooks — 서명 검증 공식 가이드",
        "url": "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
    },
    Platform.STRIPE: {
        "title": "Stripe Webhooks — 서명 검증 공식 가이드",
        "url": "https://stripe.com/docs/webhooks/signatures",
    },
    Platform.TOSS_PAYMENTS: {
        "title": "토스페이먼츠 웹훅 — 연동 보안 가이드",
        "url": "https://docs.tosspayments.com/guides/webhook/authorization",
    },
    Platform.SLACK: {
        "title": "Slack — 요청 서명 검증 가이드",
        "url": "https://api.slack.com/authentication/verifying-requests-from-slack",
    },
    Platform.PORTONE_V2: {
        "title": "PortOne V2 — 웹훅 연동 가이드",
        "url": "https://developers.portone.io/docs/ko/v2-payment/webhook",
    },
}

# SAST 규칙별 참고 링크 (플랫폼 무관)
RULE_DOC_LINKS = {
    "WHSEC-001": {
        "title": "OWASP — 웹훅 서명 검증 Best Practice",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    },
    "WHSEC-002": {
        "title": "Python docs — hmac.compare_digest (상수 시간 비교)",
        "url": "https://docs.python.org/3/library/hmac.html#hmac.compare_digest",
    },
    "WHSEC-003": {
        "title": "NIST — SHA-1 폐기 가이드라인",
        "url": "https://csrc.nist.gov/projects/hash-functions",
    },
    "WHSEC-004": {
        "title": "Stripe — 타임스탬프 허용 오차 설명",
        "url": "https://stripe.com/docs/webhooks/signatures#replay-attacks",
    },
    "WHSEC-005": {
        "title": "CWE-330 — 불충분한 랜덤성 + 우회 가능 검증",
        "url": "https://cwe.mitre.org/data/definitions/330.html",
    },
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 플랫폼 감지 엔진
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class PlatformDetector:

    def detect(self, pr: ParseResult) -> PlatformDetectionResult:
        evidence: List[str] = []
        source = "\n".join(pr.source_lines)

        # 1단계: 핸들러 파라미터 변수명으로 감지 (신뢰도 높음)
        param_platform = self._detect_from_params(pr.handlers, evidence)
        if param_platform not in (Platform.UNKNOWN, Platform.GENERIC):
            fmt = _DEFAULT_FORMATS[param_platform]
            return PlatformDetectionResult(
                filepath=pr.filepath,
                platform=param_platform,
                sig_format=fmt,
                confidence="high",
                evidence=evidence,
            )

        # 2단계: 소스 내 문자열 패턴으로 감지 (신뢰도 중간)
        str_platform = self._detect_from_strings(source, evidence)
        if str_platform not in (Platform.UNKNOWN, Platform.GENERIC):
            fmt = _DEFAULT_FORMATS[str_platform]
            return PlatformDetectionResult(
                filepath=pr.filepath,
                platform=str_platform,
                sig_format=fmt,
                confidence="medium",
                evidence=evidence,
            )

        # 3단계: Generic — 실제 헤더명 추출 시도
        if param_platform == Platform.GENERIC or str_platform == Platform.GENERIC:
            fmt = self._detect_generic_format(pr, evidence)
            return PlatformDetectionResult(
                filepath=pr.filepath,
                platform=Platform.GENERIC,
                sig_format=fmt,
                confidence="low",
                evidence=evidence,
            )

        evidence.append("서명 관련 헤더 패턴 미발견 → Unknown")
        return PlatformDetectionResult(
            filepath=pr.filepath,
            platform=Platform.UNKNOWN,
            sig_format=_DEFAULT_FORMATS[Platform.UNKNOWN],
            confidence="low",
            evidence=evidence,
        )

    # ──────────────────────────────────────────────────────
    # 내부 헬퍼
    # ──────────────────────────────────────────────────────
    def _detect_from_params(self, handlers: list, evidence: List[str]) -> Platform:
        for handler in handlers:
            node = handler.ast_node
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for arg in node.args.args:
                name = arg.arg.lower()
                if name in _GITHUB_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → GitHub")
                    return Platform.GITHUB
                if name in _STRIPE_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → Stripe")
                    return Platform.STRIPE
                if name in _TOSS_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → 토스페이먼츠")
                    return Platform.TOSS_PAYMENTS
                if name in _SLACK_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → Slack")
                    return Platform.SLACK
                if name in _PORTONE_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → PortOne V2")
                    return Platform.PORTONE_V2
                if name in _GENERIC_HEADERS:
                    evidence.append(f"파라미터: '{arg.arg}' → Generic")
                    return Platform.GENERIC
        return Platform.UNKNOWN

    def _detect_from_strings(self, source: str, evidence: List[str]) -> Platform:
        # 감지 우선순위: 토스 → Stripe → Slack → PortOne → GitHub
        checks = [
            (Platform.TOSS_PAYMENTS, _TOSS_PATTERNS),
            (Platform.STRIPE,        _STRIPE_PATTERNS),
            (Platform.SLACK,         _SLACK_PATTERNS),
            (Platform.PORTONE_V2,    _PORTONE_PATTERNS),
            (Platform.GITHUB,        _GITHUB_PATTERNS),
        ]
        for platform, patterns in checks:
            for pat in patterns:
                if re.search(pat, source, re.IGNORECASE):
                    evidence.append(f"문자열 패턴: '{pat}' → {platform.value}")
                    return platform
        return Platform.UNKNOWN

    def _detect_generic_format(self, pr: ParseResult,
                               evidence: List[str]) -> SignatureFormat:
        for handler in pr.handlers:
            node = handler.ast_node
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for arg in node.args.args:
                name = arg.arg.lower()
                if "sig" in name or "signature" in name or "hash" in name:
                    header = "-".join(p.capitalize() for p in arg.arg.split("_"))
                    evidence.append(f"Generic 헤더 추출: '{header}'")
                    return SignatureFormat(
                        platform=Platform.GENERIC,
                        sig_header=header,
                        prefix="sha256=",
                        algo="sha256",
                        predicted_tier_hint="Tier 미확정 — DAST Probe가 런타임에서 결정",
                    )
        return _DEFAULT_FORMATS[Platform.GENERIC]

    def detect_per_handler(self, pr: ParseResult) -> dict:
        """핸들러별 플랫폼 감지 (한 파일에 여러 플랫폼 혼재 시 사용)"""
        results = {}
        for handler in pr.handlers:
            sub_evidence: List[str] = []
            platform = Platform.UNKNOWN
            node = handler.ast_node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    name = arg.arg.lower()
                    mapping = [
                        (_GITHUB_HEADERS,  Platform.GITHUB),
                        (_STRIPE_HEADERS,  Platform.STRIPE),
                        (_TOSS_HEADERS,    Platform.TOSS_PAYMENTS),
                        (_SLACK_HEADERS,   Platform.SLACK),
                        (_PORTONE_HEADERS, Platform.PORTONE_V2),
                        (_GENERIC_HEADERS, Platform.GENERIC),
                    ]
                    for header_set, plat in mapping:
                        if name in header_set:
                            platform = plat
                            sub_evidence.append(f"파라미터: '{arg.arg}' → {plat.value}")
                            break
                    if platform != Platform.UNKNOWN:
                        break

            if platform == Platform.UNKNOWN:
                platform = Platform.GENERIC
                sub_evidence.append("파라미터 감지 실패 → Generic")

            fmt = _DEFAULT_FORMATS.get(platform, _DEFAULT_FORMATS[Platform.GENERIC])
            results[handler.name] = PlatformDetectionResult(
                filepath=pr.filepath,
                platform=platform,
                sig_format=fmt,
                confidence="high" if platform not in (Platform.GENERIC, Platform.UNKNOWN) else "low",
                evidence=sub_evidence,
            )
        return results
