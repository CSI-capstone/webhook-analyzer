"""
analyzer/dast.py — 동적 분석(DAST) 엔진

[역할]
  실제 동작 중인 웹훅 수신 서버에 위조 HTTP 요청을 보내
  서명 검증 취약점을 동적으로 탐지한다.

[Probe — Tier 자동 분류]
  4단계 프로브로 서버의 응답 능력을 측정하여 Tier를 결정한다.
  Step 1) 서명 없는 위조 요청 → 서버가 수락하면 즉시 CRITICAL 판정
  Step 2) 유효한 서명 요청 → 베이스라인 응답 본문/해시 기록
  Step 3) 서명 변조 요청 → 베이스라인과 응답 차이 비교
  Step 4) 상태 생성 + 조회 경로가 있으면 DB 상태 변화 관찰 → Tier 1 판정

  Tier 1 (최고 신뢰도) : 공격 전/후 상태 교차 검증 가능
  Tier 2 (중간 신뢰도) : 응답 본문 비교 가능
  Tier 3 (낮은 신뢰도) : HTTP 상태 코드만 관측 가능

[공격 종류]
  1) 다운그레이드 공격 : sha256 → sha1 → md5 → 서명 없음 순으로 시도
  2) 재전송 공격      : 만료된 타임스탬프 + 유효 서명 조합으로 시도
  3) 타입 혼동 공격   : Content-Type 변조 / 배열 래핑 / 중첩 JSON 시도

[Tier별 신뢰도 차이]
  Tier 1 : 3가지 공격 모두 상태 교차 검증으로 HIGH 신뢰도 판정 가능
  Tier 2 : 다운그레이드/재전송은 HIGH, 타입 혼동은 MEDIUM
  Tier 3 : 다운그레이드만 HIGH, 재전송/타입 혼동은 LOW (상태 코드만으로 제한적)

[주요 데이터 클래스]
  Tier          : TIER_1 / TIER_2 / TIER_3
  AttackType    : DOWNGRADE / REPLAY / TYPE_CONFUSION
  Confidence    : HIGH / MEDIUM / LOW
  ProbeResult   : Probe 결과 (Tier 판정, 각 Step 상태 코드, 연결 오류 사유)
  AttackResult  : 개별 공격 결과 (공격 유형, 취약 여부, 신뢰도, 설명, 상태 변화 여부)
  DastConfig    : 분석 설정 (URL, 시크릿, 서명 헤더, 플랫폼 정보, Tier 설정)

[DASTEngine 주요 메서드]
  run(endpoints, config) → List[AttackResult]
  _probe(endpoint, config) → ProbeResult
  _attack_downgrade(endpoint, config, tier) → AttackResult
  _attack_replay(endpoint, config, tier) → AttackResult
  _attack_type_confusion(endpoint, config, tier) → AttackResult
  _generate_mock_payload(platform_name) → dict  (플랫폼별 실제 이벤트 형식)
  _check_state_changed(config, before, after) → bool
  _query_state(config) → dict
"""

# TODO: Tier, AttackType, Confidence Enum 정의
# TODO: ProbeResult, AttackResult, DastConfig 데이터 클래스 정의
#   - ProbeResult: connection_error 필드 포함 (연결 실패 사유 기록)
#   - DastConfig: sig_header, is_stripe, is_slack, platform_name 필드 포함
# TODO: DASTEngine 클래스 구현
#   - Probe 4단계 구현
#   - 플랫폼별 mock payload 생성 (_generate_mock_payload)
#     → 빈 JSON 대신 실제 이벤트 형식을 보내야 서버가 400 대신 401 반환
#   - Stripe 서명 형식: t=<ts>,v1=<sig>
#   - Slack 서명 형식: v0=sha256(v0:<ts>:<body>)
#   - Tier별 공격 결과 신뢰도 결정 로직
#   - 상태 교차 검증 (Tier 1): 공격 전 상태 저장 → 공격 후 상태 비교
