"""
analyzer/report.py — 통합 리포트 및 등급 결정 엔진

[역할]
  SAST 탐지 결과와 DAST 공격 결과를 통합하여
  엔드포인트별 심각도 등급(CVSS 기반)과 전체 보안 점수를 산출한다.

[등급 결정 기준]
  CRITICAL  : SAST에서 CRITICAL 탐지 또는 DAST 다운그레이드 공격 성공
  HIGH      : SAST에서 HIGH 탐지 또는 DAST 재전송 공격 성공
  MEDIUM    : SAST에서 MEDIUM 탐지 또는 DAST 타입 혼동 공격 성공
  LOW       : SAST에서 LOW 탐지만 있는 경우
  INFO      : 탐지 없음

  전체 점수(overall_grade) : A / B / C / D / F 로 표시
    → A : 전체 엔드포인트에서 취약점 없음
    → F : CRITICAL 취약점 하나 이상 존재

[SAST ↔ DAST 상호 보정]
  SAST와 DAST 모두 같은 취약점을 탐지한 경우 → 신뢰도 ↑ (combined_note에 표시)
  SAST는 탐지했지만 DAST는 통과한 경우 → 신뢰도 ↓ (Tier 3에서는 흔함)

[Tier별 신뢰도 레이블]
  Tier 1 : "높음 — 상태 교차 검증 가능"
  Tier 2 : "중간 — 응답 본문 비교 기반"
  Tier 3 : "낮음 — HTTP 상태 코드만 관측 가능, 정적 분석 우선 참고"

[주요 데이터 클래스]
  EndpointReport : 엔드포인트 하나의 통합 결과
    (path, tier, sast_findings, dast_results, overall_severity, overall_cvss,
     dast_confidence, combined_note)
  FullReport : 전체 분석 결과
    (target_file, endpoints, total_sast_findings, total_dast_vulns, overall_grade)

[주요 함수]
  compute_endpoint_report(path, tier, sast_findings, dast_results) → EndpointReport
  compute_full_report(target_file, endpoint_reports) → FullReport
  print_report(full_report)  → 터미널에 컬러 출력 (CLI 전용)
"""

# TODO: EndpointReport, FullReport 데이터 클래스 정의
# TODO: 심각도 순서 상수 정의 (SEV_ORDER)
# TODO: DAST 공격 유형 → Severity 매핑 (DAST_TO_SEVERITY)
# TODO: Severity → CVSS 점수 매핑 (DAST_CVSS)
# TODO: Tier → 신뢰도 레이블 매핑 (TIER_CONFIDENCE_LABEL)
# TODO: compute_endpoint_report() 구현
#   - SAST findings 중 최고 심각도 추출
#   - DAST results에서 취약한 공격 심각도 추출
#   - 두 결과 중 더 높은 심각도 선택
#   - SAST+DAST 교차 보정 로직
#   - CVSS 점수 계산
# TODO: compute_full_report() 구현
#   - 전체 엔드포인트 집계
#   - overall_grade (A~F) 결정 로직
# TODO: print_report() 구현 (CLI 터미널 출력용, 컬러 지원)
