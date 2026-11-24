"""
analyzer/report.py

등급 결정 엔진 + 리포트 출력

SAST + DAST 결과를 통합하여:
  1) 규칙 참고 위험도와 동적 증거에 따른 등급 결정 (CRITICAL / HIGH / MEDIUM / LOW)
  2) SAST↔DAST 상호 보정 (같은 항목의 증거가 있는지 확인)
  3) Tier별 동적 분석 신뢰도 표시
  4) 엔드포인트별 Finding + 수정 코드 스니펫 출력
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from analyzer.sast import Finding, Severity
from analyzer.dast import AttackResult, ProbeResult, Tier, Confidence, AttackType, Verdict


# 통합 리포트 데이터
@dataclass
class EndpointReport:
    """엔드포인트 하나에 대한 통합 리포트"""
    path: str
    tier: Tier = Tier.TIER_2
    sast_findings: List[Finding] = field(default_factory=list)
    dast_results: List[AttackResult] = field(default_factory=list)
    overall_severity: Severity = Severity.INFO
    overall_cvss: float = 0.0
    dast_confidence: str = ""
    combined_note: str = ""
    analysis_status: str = "not_tested"
    score_basis: str = "규칙별 참고 위험도; 환경별 CVSS 산출값 아님"


@dataclass
class FullReport:
    """전체 분석 리포트"""
    target_file: str
    endpoints: List[EndpointReport] = field(default_factory=list)
    total_sast_findings: int = 0
    total_dast_vulns: int = 0
    overall_grade: str = ""
    total_dast_observations: int = 0
    total_dast_inconclusive: int = 0
    total_dast_skipped: int = 0
    analysis_status: str = "complete"


# 등급 결정
SEV_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3,
             Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}

TIER_CONFIDENCE_LABEL = {
    Tier.TIER_1: "Tier 1 — 상태 교차 검증 가능 (공격 전후 DB 상태 비교)",
    Tier.TIER_2: "Tier 2 — HTTP 응답 코드 기반 관측, SAST 결과 교차 확인 권장",
}


def compute_endpoint_report(
    path: str,
    tier: Tier,
    sast_findings: List[Finding],
    dast_results: List[AttackResult],
) -> EndpointReport:
    """엔드포인트별 등급 결정"""
    er = EndpointReport(path=path, tier=tier)
    er.sast_findings = sast_findings
    er.dast_results = dast_results
    er.dast_confidence = TIER_CONFIDENCE_LABEL.get(tier, "")

    meaningful = [f for f in sast_findings if f.severity != Severity.INFO]
    max_sev = max((f.severity for f in meaningful), key=lambda s: SEV_ORDER[s], default=Severity.INFO)
    max_cvss = max((f.cvss_score for f in meaningful), default=0.0)
    dast_vulns = [a for a in dast_results if a.status == Verdict.VULNERABLE]
    for attack in dast_vulns:
        severity = Severity.HIGH if "WHSEC-001" in attack.related_rule_ids else Severity.MEDIUM
        if SEV_ORDER[severity] > SEV_ORDER[max_sev]:
            max_sev = severity
    sast_rules = {r for f in meaningful for r in (f.related_rule_ids or [f.rule_id])}
    dynamic_rules = {r for a in dast_vulns for r in a.related_rule_ids}
    matched = sorted(sast_rules & dynamic_rules)
    if matched:
        er.combined_note = "같은 점검 항목의 정적·동적 증거 확인: " + ", ".join(matched)
    elif meaningful and dast_vulns:
        er.combined_note = "정적·동적 결과가 있으나 같은 결함의 교차 확인은 아님"
    elif dast_vulns:
        er.combined_note = "동적 처리 증거 확인; 소스 검토 권장"
    elif meaningful:
        er.combined_note = "정적 위험 징후 탐지; 동적 결과와 별도 해석"
    unfinished = any(a.status in {Verdict.OBSERVED, Verdict.INCONCLUSIVE, Verdict.SKIPPED} for a in dast_results)
    unfinished |= any(f.severity == Severity.INFO for f in sast_findings)
    er.analysis_status = "partial" if unfinished else ("complete" if dast_results else "not_tested")
    er.overall_severity = max_sev
    er.overall_cvss = max_cvss  # 탐지 신뢰도를 이유로 CVSS에 가산하지 않는다.
    return er


def compute_full_report(
    target_file: str,
    endpoint_reports: List[EndpointReport],
) -> FullReport:
    """전체 리포트 생성"""
    r = FullReport(target_file=target_file, endpoints=endpoint_reports)
    # INFO 등급(WHSEC-DYN 등)은 실제 취약점이 아니므로 집계에서 제외
    r.total_sast_findings = sum(
        len([f for f in er.sast_findings if f.severity != Severity.INFO])
        for er in endpoint_reports
    )
    r.total_dast_vulns = sum(
        len([a for a in er.dast_results if a.vulnerable])
        for er in endpoint_reports)

    attacks = [a for endpoint in endpoint_reports for a in endpoint.dast_results]
    r.total_dast_observations = sum(a.status == Verdict.OBSERVED for a in attacks)
    r.total_dast_inconclusive = sum(a.status == Verdict.INCONCLUSIVE for a in attacks)
    r.total_dast_skipped = sum(a.status == Verdict.SKIPPED for a in attacks)
    partial = any(e.analysis_status == "partial" for e in endpoint_reports)
    r.analysis_status = "partial" if partial else ("sast_only" if not attacks else "complete")
    maximum = max((e.overall_severity for e in endpoint_reports), key=lambda s: SEV_ORDER[s], default=Severity.INFO)
    grades = {Severity.CRITICAL: "F — 즉시 검토 필요", Severity.HIGH: "D — 주요 위험 징후",
              Severity.MEDIUM: "C — 개선·검토 필요", Severity.LOW: "B — 경미한 위험 징후"}
    if maximum in grades:
        r.overall_grade = grades[maximum]
    elif not endpoint_reports:
        r.overall_grade = "N/A — 분석 대상 없음"
        r.analysis_status = "partial"
    elif partial:
        r.overall_grade = "N/A — 추가 확인 필요"
    else:
        r.overall_grade = "A — 점검 범위 내 미탐지"

    return r


# 텍스트 리포트 출력
def print_report(report: FullReport):
    W = 70
    print("\n" + "=" * W)
    print("  웹훅 보안 분석 리포트")
    print("=" * W)
    print(f"  대상: {report.target_file}")
    print(f"  전체 등급: {report.overall_grade}")
    print(f"  SAST 탐지: {report.total_sast_findings}건")
    print(f"  DAST 확인: {report.total_dast_vulns}건 | 수락 관측: {report.total_dast_observations}건 | 판단 불가: {report.total_dast_inconclusive}건 | 생략: {report.total_dast_skipped}건")

    for er in report.endpoints:
        print(f"\n{'─' * W}")
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                     "LOW": "🟢", "INFO": "⚪"}.get(er.overall_severity.value, "")
        print(f"  {sev_icon} {er.path}")
        print(f"  등급: {er.overall_severity.value} | "
              f"참고 위험도: {er.overall_cvss:.1f} | {er.tier.value}")
        print(f"  동적분석 신뢰도: {er.dast_confidence}")
        if er.combined_note:
            print(f"  교차 검토: {er.combined_note}")

        # SAST Findings
        if er.sast_findings:
            print(f"\n  [정적 분석]")
            for f in er.sast_findings:
                print(f"    {f.rule_id} {f.severity.value:8s} "
                      f"L{f.lineno:3d} | {f.message}")
                if f.recommendation:
                    print(f"      수정: {f.recommendation}")
                if f.fix_snippet:
                    print(f"      ┌─ 수정 코드 스니펫 ─┐")
                    for line in f.fix_snippet.strip().split("\n")[:12]:
                        print(f"      │ {line}")
                    if len(f.fix_snippet.strip().split("\n")) > 12:
                        print(f"      │ ... (이하 생략)")
                    print(f"      └───────────────────┘")

        # DAST Results
        dast_vulns = [a for a in er.dast_results if a.vulnerable]
        dast_safe = [a for a in er.dast_results if not a.vulnerable]
        if dast_vulns:
            print(f"\n  [동적 분석 — 취약점]")
            for a in dast_vulns:
                print(f"    🔴 {a.attack_type.value:16s} "
                      f"{a.confidence.value:6s} | {a.description}")
                for d in a.details:
                    print(f"       {d}")
        if dast_safe:
            print(f"\n  [동적 분석 — 거부·관측·미완료]")
            for a in dast_safe:
                print(f"    [{a.status.value}] {a.attack_type.value:16s} | {a.description}")

    print(f"\n{'=' * W}")
    print(f"  리포트 끝")
    print(f"{'=' * W}\n")


def group_findings(parse_results, findings):
    """외부 결함 위치(filepath)와 호출 핸들러 위치(origin_filepath)를 구분한다."""
    lookup = {(pr.filepath, handler.name): handler.route_path
              for pr in parse_results for handler in pr.handlers}
    first_paths = {pr.filepath: pr.handlers[0].route_path for pr in parse_results if pr.handlers}
    grouped = {path: [] for path in lookup.values()}
    for finding in findings:
        source = finding.origin_filepath or finding.filepath
        path = lookup.get((source, finding.handler_name))
        if finding.handler_name in {'(파일 전체)', '(모듈 레벨)'}:
            path = first_paths.get(source)
        if path in grouped:
            grouped[path].append(finding)
    return grouped
