"""
tests/test_integration.py

D14 — 전체 파이프라인 End-to-End 통합 테스트

실행 순서:
  1) SAST: vulnerable_webhook.py 분석 → 7건 Finding 확인
  2) SAST: secure_webhook.py 분석 → 0건 확인
  3) 테스트 서버 기동
  4) Probe: 6개 엔드포인트 Tier 분류
  5) DAST: 다운그레이드 + 재전송 + 타입혼동 공격
  6) 신규 공격: 크로스 페이로드 + 플랫폼별 엔드포인트 검증
  7) 등급 결정 + 리포트 생성

테스트 환경:
  - Python 3.10+ (stdlib만으로 SAST 동작)
  - requests 패키지 (DAST용)
  - 포트 9200에서 테스트 서버 자동 기동

실행 방법:
  cd webhook-sast-v2
  python tests/test_integration.py
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.engine import WebhookASTEngine
from analyzer.sast import SASTEngine, Finding, Severity
from analyzer.dast import DASTEngine, DastConfig, Tier, AttackType  # DOWNGRADE, REPLAY, TYPE_CONFUSION
from analyzer.report import (
    compute_endpoint_report, compute_full_report, print_report,
    EndpointReport,
)
from server.test_server import start_server, reset_db

PORT = 9200
BASE = f"http://127.0.0.1:{PORT}"
SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

# 엔드포인트별 서명 헤더 매핑
SIG_MAP = {
    "/webhook/no-verify": "X-Hub-Signature-256",
    "/webhook/timing-attack": "X-Hub-Signature-256",
    "/webhook/weak-hash-sha1": "X-Hub-Signature",
    "/webhook/weak-hash-md5": "X-Signature",
    "/webhook/no-timestamp": "X-Hub-Signature-256",
    "/webhook/secure": "X-Hub-Signature-256",
}

WEBHOOK_ENDPOINTS = list(SIG_MAP.keys())


def h1(t):
    print(f"\n{'━' * 70}\n  {t}\n{'━' * 70}")

def h2(t):
    print(f"\n  {'─' * 58}\n  {t}\n  {'─' * 58}")

def check(label, ok):
    print(f"  {'✅' if ok else '❌'} {label}")
    return ok


def main():
    all_ok = True

    h1("PHASE 1: 정적 분석 (SAST)")
    sast = SASTEngine()

    # 취약 서버 분석
    h2("취약 서버 (vulnerable_webhook.py)")
    vuln_findings = sast.analyze_file(os.path.join(SAMPLES, "vulnerable_webhook.py"))
    print(f"  Finding: {len(vuln_findings)}건")
    for f in vuln_findings:
        print(f"    {f.rule_id} {f.severity.value:8s} | {f.handler_name:30s} | {f.message[:50]}")

    # 규칙별 검증
    r01 = [f for f in vuln_findings if f.rule_id == "WHSEC-001"]
    r02 = [f for f in vuln_findings if f.rule_id == "WHSEC-002"]
    r03 = [f for f in vuln_findings if f.rule_id == "WHSEC-003"]
    r04 = [f for f in vuln_findings if f.rule_id == "WHSEC-004"]
    r05 = [f for f in vuln_findings if f.rule_id == "WHSEC-005"]

    h2("SAST 검증")
    all_ok &= check("Rule 1: 서명 누락 1건", len(r01) == 1)
    all_ok &= check("Rule 2: 타이밍공격 2건 (직접+위임)", len(r02) == 2)
    all_ok &= check("Rule 3: 취약해시 2건 (SHA1+MD5)", len(r03) == 2)
    all_ok &= check("Rule 4: 타임스탬프 누락 1건", len(r04) == 1)
    all_ok &= check("Rule 5: 외부위임 결함 1건+", len(r05) >= 1)

    # 수정 코드 스니펫 존재 확인
    snippets_present = sum(1 for f in vuln_findings if f.fix_snippet)
    all_ok &= check(f"수정 코드 스니펫 {snippets_present}건 생성",
                     snippets_present >= 5)

    # 안전 서버 분석
    h2("안전 서버 (secure_webhook.py)")
    safe_findings = sast.analyze_file(os.path.join(SAMPLES, "secure_webhook.py"))
    print(f"  Finding: {len(safe_findings)}건")
    all_ok &= check("안전 서버 0건 (오탐 없음)", len(safe_findings) == 0)

    h1("PHASE 2: 동적 분석 (DAST)")

    # 서버 기동
    reset_db()
    srv = start_server(PORT)
    time.sleep(0.3)
    print(f"  서버 시작: {BASE}")

    try:
        dast = DASTEngine(DastConfig(base_url=BASE))

        # Probe
        h2("Probe — Tier 분류")
        probes = {}
        for ep in WEBHOOK_ENDPOINTS:
            reset_db()
            pr = dast.probe(ep, SIG_MAP[ep])
            probes[ep] = pr
            icon = {"Tier 1": "🟢", "Tier 2": "🟡"}.get(pr.tier.value, "")
            flag = " ⚠V1" if pr.step1_accepted else ""
            print(f"  {icon} {pr.tier.value} {ep:30s}"
                  f" 1:{pr.step1_code}{flag} 2:{pr.step2_code}"
                  f" 3:{pr.step3_code} 4:{'✓' if pr.step4_state_ok else '✗'}")

        all_ok &= check("전체 Tier 1 (상태조회 가능)",
                         all(p.step4_state_ok for p in probes.values()))

        # 공격 실행
        h2("DAST 공격 — 다운그레이드 + 재전송 + 타입혼동")
        all_attacks = {}
        for ep in WEBHOOK_ENDPOINTS:
            reset_db()
            # 엔드포인트별 서명 헤더를 run_all에 전달
            attacks = dast.run_all(ep, probes[ep], SIG_MAP[ep])
            all_attacks[ep] = attacks
            vulns = [a for a in attacks if a.vulnerable]
            if vulns:
                for a in vulns:
                    print(f"  🔴 {ep:30s} {a.attack_type.value:16s} "
                          f"{a.confidence.value:6s} | {a.description[:45]}")
            else:
                print(f"  🟢 {ep:30s} 전공격 거부")

        h2("DAST 검증")

        # V1: 다운그레이드(서명없음) 수락
        nv = all_attacks.get("/webhook/no-verify", [])
        all_ok &= check("V1 서명없음 수락",
                         any(a.vulnerable and a.attack_type == AttackType.DOWNGRADE for a in nv))

        # V2: 타이밍 공격 (== 비교) — /webhook/timing-attack은 타임스탬프를 정상 검증하므로 DAST REPLAY는 거부됨
        # == 비교 취약점은 SAST 결과로 검증
        ta_sast = [f for f in vuln_findings
                   if f.handler_name == "webhook_timing_attack"
                   and f.rule_id == "WHSEC-002"]
        all_ok &= check("V2 타이밍공격 SAST 검출",
                         len(ta_sast) >= 1)

        # V3a: SHA1 다운그레이드 수락
        s1 = all_attacks.get("/webhook/weak-hash-sha1", [])
        all_ok &= check("V3a SHA1 다운그레이드 수락",
                         any(a.vulnerable and a.attack_type == AttackType.DOWNGRADE for a in s1))

        # V3b: MD5 다운그레이드 수락
        m5 = all_attacks.get("/webhook/weak-hash-md5", [])
        all_ok &= check("V3b MD5 다운그레이드 수락",
                         any(a.vulnerable and a.attack_type == AttackType.DOWNGRADE for a in m5))

        # V4: 재전송 수락
        nt = all_attacks.get("/webhook/no-timestamp", [])
        all_ok &= check("V4 재전송 수락",
                         any(a.vulnerable and a.attack_type == AttackType.REPLAY for a in nt))

        # 안전: 전공격 거부
        sc = all_attacks.get("/webhook/secure", [])
        all_ok &= check("S 전공격 거부 (안전)",
                         all(not a.vulnerable for a in sc))

        # 타입혼동: 취약 엔드포인트에서 일부 수락, 안전에서 거부
        tc_safe = [a for a in sc if a.attack_type == AttackType.TYPE_CONFUSION]
        all_ok &= check("S 타입혼동 거부 (안전)",
                         all(not a.vulnerable for a in tc_safe))

        h1("PHASE 2.5: 플랫폼별 엔드포인트 검증")

        PLATFORM_CASES = [
            # (엔드포인트, sig_header, platform_name, is_stripe, is_slack, 기대 공격유형, 설명)
            ("/webhook/stripe",  "Stripe-Signature",                  "stripe",  True,  False,
             AttackType.REPLAY,    "Stripe 재전송 수락 — 타임스탬프 미검증"),
            ("/webhook/toss",    "TossPayments-Webhook-Signature",    "toss",    False, False,
             AttackType.REPLAY,    "Toss 재전송 수락 — 타임스탬프 미검증 (== 비교는 SAST로 탐지)"),
            ("/webhook/slack",   "X-Slack-Signature",                 "slack",   False, True,
             AttackType.REPLAY,    "Slack 재전송 수락 — 타임스탬프 미검증"),
            ("/webhook/portone", "webhook-signature",                 "portone", False, False,
             AttackType.DOWNGRADE, "PortOne 서명 검증 누락 — 다운그레이드 수락"),
        ]

        for ep, sig_hdr, pname, is_stripe, is_slack, expected_type, label in PLATFORM_CASES:
            reset_db()
            p_cfg = DastConfig(
                base_url=BASE,
                sig_header=sig_hdr,
                platform_name=pname,
                is_stripe=is_stripe,
                is_slack=is_slack,
            )
            p_dast = DASTEngine(p_cfg)
            p_probe = p_dast.probe(ep, sig_hdr)
            p_attacks = p_dast.run_all(ep, p_probe, sig_hdr)
            p_vulns = [a for a in p_attacks if a.vulnerable]
            found = any(a.vulnerable and a.attack_type == expected_type for a in p_attacks)
            all_ok &= check(label, found)
            if p_vulns:
                for a in p_vulns:
                    print(f"       🔴 {a.attack_type.value:16s} {a.confidence.value} | {a.description[:45]}")

        h1("PHASE 3: 등급 결정 + 리포트")

        # 엔드포인트별 SAST Finding 매핑
        handler_to_path = {
            "webhook_no_verify": "/webhook/no-verify",
            "webhook_timing_attack": "/webhook/timing-attack",
            "webhook_weak_hash_sha1": "/webhook/weak-hash-sha1",
            "webhook_weak_hash_md5": "/webhook/weak-hash-md5",
            "webhook_no_timestamp": "/webhook/no-timestamp",
            "webhook_secure": "/webhook/secure",
            "webhook_delegated": "/webhook/no-verify",  # delegated는 별도 경로 없으니 매핑
            "webhook_delegated_external": "/webhook/no-verify",
        }

        ep_sast: dict = {ep: [] for ep in WEBHOOK_ENDPOINTS}
        for f in vuln_findings:
            p = handler_to_path.get(f.handler_name)
            if p and p in ep_sast:
                ep_sast[p].append(f)

        # 모듈 레벨 Finding(WHSEC-006 등)은 handler_name이 "(모듈 레벨)"이라
        # handler_to_path 매핑에서 누락됨 → 첫 번째 엔드포인트에 fallback 추가
        MODULE_LEVEL_NAMES = {"(모듈 레벨)", "(파일 전체)"}
        unmatched_module = [
            f for f in vuln_findings
            if f.handler_name in MODULE_LEVEL_NAMES
        ]
        if unmatched_module and WEBHOOK_ENDPOINTS:
            ep_sast[WEBHOOK_ENDPOINTS[0]].extend(unmatched_module)

        # 엔드포인트별 리포트 생성
        ep_reports = []
        for ep in WEBHOOK_ENDPOINTS:
            er = compute_endpoint_report(
                ep, probes[ep].tier,
                ep_sast.get(ep, []),
                all_attacks.get(ep, []),
            )
            ep_reports.append(er)

        full = compute_full_report("vulnerable_webhook.py", ep_reports)
        print_report(full)

        # 리포트 검증
        h2("리포트 검증")
        all_ok &= check(f"전체 등급 F (CRITICAL 존재)",
                         "F" in full.overall_grade)
        all_ok &= check(f"SAST {full.total_sast_findings}건",
                         full.total_sast_findings >= 7)
        all_ok &= check(f"DAST {full.total_dast_vulns}건",
                         full.total_dast_vulns >= 4)

    finally:
        srv.shutdown()

    h1("최종 결과")
    if all_ok:
        print("  🎉 전체 파이프라인 통과!")
    else:
        print("  ⚠  일부 검증 실패")
    print()
    return all_ok


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
