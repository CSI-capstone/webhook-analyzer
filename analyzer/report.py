"""
analyzer/report.py

D12-D13 — 등급 결정 엔진 + 리포트 출력
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SAST + DAST 결과를 통합하여:
  1) CVSS v3.1 기반 등급 결정 (CRITICAL / HIGH / MEDIUM / LOW)
  2) SAST↔DAST 상호 보정 (둘 다 탐지 시 신뢰도 ↑)
  3) Tier별 동적 분석 신뢰도 표시
  4) 엔드포인트별 Finding + 수정 코드 스니펫 출력
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from analyzer.sast import Finding, Severity
from analyzer.dast import AttackResult, ProbeResult, Tier, Confidence, AttackType


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 통합 리포트 데이터
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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


@dataclass
class FullReport:
    """전체 분석 리포트"""
    target_file: str
    endpoints: List[EndpointReport] = field(default_factory=list)
    total_sast_findings: int = 0
    total_dast_vulns: int = 0
    overall_grade: str = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 등급 결정
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEV_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3,
             Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}

TIER_CONFIDENCE_LABEL = {
    Tier.TIER_1: "높음 — 상태 교차 검증 가능",
    Tier.TIER_2: "낮음 — HTTP 상태 코드만 관측 가능, 정적 분석(SAST) 결과 우선 참고",
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

    # 최고 심각도 결정 (SAST + DAST 통합)
    max_sev = Severity.INFO
    max_cvss = 0.0

    for f in sast_findings:
        if SEV_ORDER[f.severity] > SEV_ORDER[max_sev]:
            max_sev = f.severity
        max_cvss = max(max_cvss, f.cvss_score)

    # SAST + DAST 둘 다 탐지 시 보정 (등급은 SAST 기준, DAST는 신뢰도 보완만)
    sast_vulns = {f.rule_id for f in sast_findings}
    dast_vulns = {ar.attack_type for ar in dast_results if ar.vulnerable}

    if sast_vulns and dast_vulns:
        er.combined_note = "SAST+DAST 모두 탐지 → 신뢰도 매우 높음"
        max_cvss = min(max_cvss + 0.5, 10.0)
    elif sast_vulns and not dast_vulns:
        er.combined_note = "SAST만 탐지 — 동적 환경에서 추가 확인 권장"
    elif dast_vulns and not sast_vulns:
        er.combined_note = "DAST만 탐지 — CVSS 근거 없음, 소스 코드 직접 검토 권장"

    er.overall_severity = max_sev
    er.overall_cvss = max_cvss
    return er


def compute_full_report(
    target_file: str,
    endpoint_reports: List[EndpointReport],
) -> FullReport:
    """전체 리포트 생성"""
    r = FullReport(target_file=target_file, endpoints=endpoint_reports)
    # 버그 23 수정: INFO 등급(WHSEC-DYN 등) 제외하고 실제 취약점만 집계
    # INFO 1건만 있어도 A → C 강등되는 오동작 방지
    r.total_sast_findings = sum(
        len([f for f in er.sast_findings if f.severity != Severity.INFO])
        for er in endpoint_reports
    )
    r.total_dast_vulns = sum(
        len([a for a in er.dast_results if a.vulnerable])
        for er in endpoint_reports)

    # 전체 등급
    has_crit = any(er.overall_severity == Severity.CRITICAL for er in endpoint_reports)
    has_high = any(er.overall_severity == Severity.HIGH for er in endpoint_reports)
    has_medium = any(er.overall_severity == Severity.MEDIUM for er in endpoint_reports)
    has_low = any(er.overall_severity == Severity.LOW for er in endpoint_reports)
    if has_crit:
        r.overall_grade = "F — 즉시 수정 필요"
    elif has_high:
        r.overall_grade = "D — 주요 취약점 존재"
    elif has_medium:
        r.overall_grade = "C — 개선 필요"
    elif has_low:
        r.overall_grade = "B — 경미한 취약점"
    else:
        r.overall_grade = "A — 양호"

    return r


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 텍스트 리포트 출력
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_report(report: FullReport):
    W = 70
    print("\n" + "=" * W)
    print("  웹훅 보안 분석 리포트")
    print("=" * W)
    print(f"  대상: {report.target_file}")
    print(f"  전체 등급: {report.overall_grade}")
    print(f"  SAST 탐지: {report.total_sast_findings}건")
    print(f"  DAST 탐지: {report.total_dast_vulns}건")

    for er in report.endpoints:
        print(f"\n{'─' * W}")
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                     "LOW": "🟢", "INFO": "⚪"}.get(er.overall_severity.value, "")
        print(f"  {sev_icon} {er.path}")
        print(f"  등급: {er.overall_severity.value} | "
              f"CVSS: {er.overall_cvss:.1f} | {er.tier.value}")
        print(f"  동적분석 신뢰도: {er.dast_confidence}")
        if er.combined_note:
            print(f"  보정: {er.combined_note}")

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
            print(f"\n  [동적 분석 — 안전]")
            for a in dast_safe:
                print(f"    🟢 {a.attack_type.value:16s} | {a.description}")

    print(f"\n{'=' * W}")
    print(f"  리포트 끝")
    print(f"{'=' * W}\n")