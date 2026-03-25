"""
analyzer/serializer.py — JSON 직렬화 모듈

[역할]
  dataclass 기반의 분석 결과 객체들을 FastAPI 응답에 사용 가능한
  JSON 직렬화 가능한 dict 형태로 변환한다.

[변환 대상 및 출력 필드]
  finding_to_dict(Finding) → dict
    rule_id, rule_name, severity, message, filepath, handler_name,
    lineno, end_lineno, cvss_score, recommendation, fix_snippet, code_snippet

  attack_result_to_dict(AttackResult) → dict
    attack_type, endpoint, tier, vulnerable, confidence,
    description, details, status_code, state_changed

  probe_result_to_dict(ProbeResult) → dict
    endpoint, tier, step1_code, step1_accepted, step2_code, step3_code,
    step3_body, step4_state_ok, details, connection_error

  endpoint_report_to_dict(EndpointReport) → dict
    path, tier, overall_severity, overall_cvss, dast_confidence, combined_note,
    sast_findings (list), dast_results (list)

  full_report_to_dict(FullReport) → dict
    target_file, endpoints (list), total_sast_findings,
    total_dast_vulns, overall_grade, elapsed_sec,
    platform (플랫폼 감지 결과), platform_doc (공식 문서 링크),
    has_router_split, dast_ran, dast_warnings, files_analyzed, warning
"""

# TODO: finding_to_dict() 구현
# TODO: attack_result_to_dict() 구현
# TODO: probe_result_to_dict() 구현
#   - step3_body, connection_error 필드 포함 (Tier 2 판정 근거)
# TODO: endpoint_report_to_dict() 구현
# TODO: full_report_to_dict() 구현
#   - platform 정보를 플랫폼 이름, 헤더명, 알고리즘 등으로 분해하여 포함
#   - elapsed_sec, dast_ran, dast_warnings, files_analyzed 등 메타 정보 포함
