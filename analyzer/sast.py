"""
analyzer/sast.py — 정적 분석(SAST) 엔진

[역할]
  ParseResult(AST 파싱 결과)를 입력받아 웹훅 보안 취약점을 탐지한다.
  각 규칙은 Finding 객체를 생성하며, 수정 코드 스니펫(fix_snippet)도 함께 생성한다.

[탐지 규칙]
  WHSEC-001 (CRITICAL) : 서명 검증 자체가 없음
    - 핸들러 함수 내에 HMAC 검증 호출이 전혀 없는 경우
    - 외부 위임 함수도 내부적으로 서명 검증을 하지 않는 경우

  WHSEC-002 (HIGH)     : 타이밍 공격 취약 비교 (== 사용)
    - hmac.compare_digest 대신 == 로 서명 문자열을 비교하는 경우
    - import 추적으로 외부 파일의 == 비교도 탐지

  WHSEC-003 (HIGH/CRITICAL) : 취약한 해시 알고리즘 사용
    - SHA1 또는 MD5 를 HMAC 알고리즘으로 사용하는 경우

  WHSEC-004 (MEDIUM)   : 타임스탬프 검증 없음
    - 재전송 공격 방지를 위한 타임스탬프 검증 로직이 없는 경우

  WHSEC-005 (HIGH)     : 외부 파일 위임 결함
    - 서명 검증을 외부 함수에 위임했는데 해당 함수 내부에 결함이 있는 경우
    - engine.resolve_import() 로 import 추적하여 탐지

[Finding 데이터 구조]
  rule_id, rule_name, severity, message, filepath, handler_name,
  lineno, end_lineno, cvss_score, recommendation, fix_snippet, code_snippet

[SASTEngine 주요 메서드]
  analyze_file(filepath)     → List[Finding] (단일 파일 분석)
  analyze(parse_result)      → List[Finding] (파싱 결과로 분석)
  _check_rule_001(handler, parse_result) → List[Finding]
  _check_rule_002(handler, parse_result) → List[Finding]
  _check_rule_003(handler, parse_result) → List[Finding]
  _check_rule_004(handler, parse_result) → List[Finding]
  _check_rule_005(handler, parse_result) → List[Finding]
  _generate_fix_snippet(rule_id, handler) → str  (수정 코드 자동 생성)
"""

# TODO: Severity Enum 정의 (CRITICAL, HIGH, MEDIUM, LOW, INFO)
# TODO: Finding 데이터 클래스 정의
# TODO: 탐지 패턴 상수 정의
#   - VERIFY_CALL_PATTERNS  : hmac.new, hmac.compare_digest, hmac.digest
#   - VERIFY_NAME_KEYWORDS  : verify, validate, check_sig 등
#   - SIG_VAR_KEYWORDS      : sig, signature, hash, computed 등
#   - WEAK_ALGORITHMS       : sha1, md5
#   - TIMESTAMP_KEYWORDS    : timestamp, time, ts, nonce 등
#   - TIMESTAMP_HEADER_STRINGS : x-timestamp, x-slack-request-timestamp 등
#   - TIME_CALL_PATTERNS    : time.time, datetime.now 등
# TODO: SASTEngine 클래스 구현
#   - 각 규칙별 탐지 메서드
#   - import 추적 로직 (rule 001, 005)
#   - fix_snippet 자동 생성 로직
