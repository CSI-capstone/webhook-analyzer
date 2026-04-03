"""
analyzer/serializer.py

SAST / DAST / Report 결과 객체를 JSON 직렬화 가능한 dict 로 변환
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from typing import Any

from analyzer.sast import Finding, Severity
from analyzer.dast import AttackResult, ProbeResult, AttackType, Confidence, Tier
from analyzer.report import EndpointReport, FullReport


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Finding (SAST)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id":       f.rule_id,
        "rule_name":     f.rule_name,
        "severity":      f.severity.value,
        "message":       f.message,
        "filepath":      f.filepath,
        "handler_name":  f.handler_name,
        "lineno":        f.lineno,
        "end_lineno":    f.end_lineno,
        "cvss_score":    f.cvss_score,
        "recommendation": f.recommendation,
        "fix_snippet":   f.fix_snippet,
        "code_snippet":  f.code_snippet,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AttackResult (DAST)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def attack_result_to_dict(a: AttackResult) -> dict:
    return {
        "attack_type":   a.attack_type.value,
        "endpoint":      a.endpoint,
        "tier":          a.tier.value,
        "vulnerable":    a.vulnerable,
        "confidence":    a.confidence.value,
        "description":   a.description,
        "details":       a.details,
        "status_code":   a.status_code,
        "state_changed": a.state_changed,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ProbeResult
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def probe_result_to_dict(p: ProbeResult) -> dict:
    return {
        "endpoint":        p.endpoint,
        "tier":            p.tier.value,
        "step1_code":      p.step1_code,
        "step1_accepted":  p.step1_accepted,
        "step2_code":      p.step2_code,
        "step3_code":      p.step3_code,
        "step3_body":      p.step3_body,       # 유효 서명 응답 본문 (디버깅용)
        "step4_state_ok":  p.step4_state_ok,
        "details":         p.details,
        "connection_error": p.connection_error, # 버그 16 수정: v2 신규 필드 추가 (연결 오류 사유)
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EndpointReport
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def endpoint_report_to_dict(er: EndpointReport) -> dict:
    return {
        "path":             er.path,
        "tier":             er.tier.value,
        "overall_severity": er.overall_severity.value,
        "overall_cvss":     er.overall_cvss,
        "dast_confidence":  er.dast_confidence,
        "combined_note":    er.combined_note,
        "sast_findings":    [finding_to_dict(f) for f in er.sast_findings],
        "dast_results":     [attack_result_to_dict(a) for a in er.dast_results],
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FullReport  ← 최종 API 응답에 사용
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def full_report_to_dict(report: FullReport) -> dict:
    return {
        "target_file":         report.target_file,
        "overall_grade":       report.overall_grade,
        "total_sast_findings": report.total_sast_findings,
        "total_dast_vulns":    report.total_dast_vulns,
        "endpoints":           [endpoint_report_to_dict(er) for er in report.endpoints],
    }
