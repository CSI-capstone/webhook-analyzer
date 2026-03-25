"""
analyzer/platform.py — 플랫폼 자동 감지 모듈

[역할]
  ParseResult(AST 파싱 결과)에서 웹훅 서명 헤더 이름 및 변수명을 분석하여
  어떤 외부 서비스(GitHub, Stripe, Slack 등)의 웹훅인지 자동 판별한다.

[지원 플랫폼]
  Platform.GITHUB        : X-Hub-Signature-256 헤더 사용, sha256= 접두사
  Platform.STRIPE        : Stripe-Signature 헤더, t=<ts>,v1=<sig> 형식
  Platform.TOSS_PAYMENTS : tosspayments-webhook-signature 헤더
  Platform.SLACK         : X-Slack-Signature 헤더, v0=sha256_sig 형식
  Platform.PORTONE_V2    : webhook-signature 헤더 (Standard Webhooks 준수)
  Platform.GENERIC       : 알 수 없는 커스텀 서명 방식
  Platform.UNKNOWN       : 서명 헤더 자체가 없음

[SignatureFormat 데이터 클래스]
  platform        : Platform enum 값
  sig_header      : 실제 HTTP 헤더명 (예: "X-Hub-Signature-256")
  prefix          : HMAC 결과 앞에 붙는 접두사 (예: "sha256=")
  algo            : hashlib 알고리즘명 (예: "sha256")
  is_stripe       : True이면 t=<ts>,v1=<sig> 조립 방식 사용
  is_slack        : True이면 v0=<ts>:<body> 조립 방식 사용
  predicted_tier_hint : 예상 Tier 힌트 ("Tier 1 예상" 등)

[PlatformDetectionResult 데이터 클래스]
  filepath    : 분석 대상 파일 경로
  platform    : 감지된 플랫폼
  sig_format  : 서명 형식 정보
  confidence  : 감지 신뢰도 ("high" / "medium" / "low")
  evidence    : 감지 근거 문자열 목록

[PlatformDetector 주요 메서드]
  detect(parse_result) → PlatformDetectionResult
  _match_header_params(handler) → Optional[Platform]  (함수 파라미터명으로 매핑)
  _match_string_literals(handler) → Optional[Platform]  (문자열 리터럴로 매핑)
  _infer_sig_format(platform) → SignatureFormat

[PLATFORM_DOC_LINKS]
  각 플랫폼별 공식 보안 문서 URL 딕셔너리
  (웹 UI의 "플랫폼 공식 보안 가이드" 배너에 표시)
"""

# TODO: Platform Enum 정의 (GITHUB, STRIPE, TOSS_PAYMENTS, SLACK, PORTONE_V2, GENERIC, UNKNOWN)
# TODO: SignatureFormat, PlatformDetectionResult 데이터 클래스 정의
# TODO: 헤더 변수명 → 플랫폼 매핑 상수 정의
#   - _GITHUB_HEADERS  : x_hub_signature_256, x_hub_signature
#   - _STRIPE_HEADERS  : stripe_signature, stripe_sig
#   - _TOSS_HEADERS    : tosspayments_webhook_signature 등
#   - _SLACK_HEADERS   : x_slack_signature, x_slack_request_timestamp
#   - _PORTONE_HEADERS : webhook_signature, portone_signature
# TODO: PLATFORM_DOC_LINKS 딕셔너리 정의 (플랫폼 → {title, url})
# TODO: PlatformDetector 클래스 구현
#   - 파라미터명 기반 감지 (snake_case HTTP 헤더명)
#   - 문자열 리터럴 기반 감지 (헤더명 직접 비교)
#   - 신뢰도 결정 로직 (파라미터명 일치 = high, 문자열만 = medium)
#   - 각 플랫폼별 SignatureFormat 생성
