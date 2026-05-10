"""
main.py

웹훅 보안 취약점 자동 탐지 프레임워크 — 메인 진입점

사용법:
  python main.py \\
      --code <python_file> \\
      --url  <webhook_base_url> \\
      [--state-create  <path>]      예: /orders
      [--state-query   <template>]  예: /orders/{id}
      [--secret        <secret_key>]
      [--sast-only]
      [--dast-only]

예시:
  # 취약 서버 전체 분석
  python main.py \\
      --code samples/vulnerable_webhook.py \\
      --url  http://localhost:8000 \\
      --state-create /orders \\
      --state-query  /orders/{id}

  # 코드만 정적 분석
  python main.py --code samples/secure_webhook.py --sast-only

  # Stripe 스타일 웹훅 (상태 조회 URL 없음 → Tier 2 자동 감지)
  python main.py \\
      --code my_stripe_handler.py \\
      --url  http://localhost:8000

파이프라인:
  [1] 입력 파싱 + 유효성 검사
  [2] 플랫폼 감지 (analyzer/platform.py)
  [3] 정적 분석 SAST (analyzer/sast.py)
  [4] 동적 분석 DAST + Probe (analyzer/dast.py)
       - Probe: Tier 1/2 런타임 결정
       - 공격: 다운그레이드, 재전송, 타입 혼동
  [5] 통합 리포트 (analyzer/report.py)
       - CVSS 등급, Tier 신뢰도, 수정 코드 스니펫
"""

import argparse
import os
import sys
import time

# 경로 설정 (모듈 임포트를 위해 프로젝트 루트를 sys.path에 추가)
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzer.engine import WebhookASTEngine
from analyzer.sast import SASTEngine, Finding
from analyzer.dast import DASTEngine, DastConfig, Tier
from analyzer.report import (
    compute_endpoint_report,
    compute_full_report,
    print_report,
    EndpointReport,
)

# platform.py는 analyzer 패키지 내에 있다고 가정
# 아직 패키지에 없다면 단독 파일로도 동작하도록 try/except 처리
try:
    from analyzer.platform import PlatformDetector, Platform
    _PLATFORM_AVAILABLE = True
except ImportError:
    _PLATFORM_AVAILABLE = False

# CLI 파서
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhook-analyzer",
        description="웹훅 핸들러 보안 취약점 자동 탐지 프레임워크",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--code", required=True, metavar="FILE",
        help="분석할 Python 웹훅 핸들러 파일 경로",
    )
    p.add_argument(
        "--url", metavar="URL",
        help="웹훅 수신 서버 base URL (DAST에 필요). 예: http://localhost:8000",
    )
    p.add_argument(
        "--state-create", metavar="PATH", default="/orders",
        help="[Tier 1] 상태 생성 엔드포인트 경로 (선택). 예: /orders",
    )
    p.add_argument(
        "--state-query", metavar="TEMPLATE", default="/orders/{id}",
        help="[Tier 1] 상태 조회 경로 템플릿 (선택). 예: /orders/{id}",
    )
    p.add_argument(
        "--secret", metavar="SECRET", default=None,
        help="HMAC 서명에 사용할 시크릿 키 (선택 — 미입력 시 재전송 공격 생략)",
    )
    p.add_argument(
        "--timeout", type=float, default=5.0,
        help="DAST HTTP 요청 타임아웃 (초, 기본값: 5.0)",
    )
    p.add_argument(
        "--sast-only", action="store_true",
        help="정적 분석만 수행 (DAST 건너뜀)",
    )
    p.add_argument(
        "--dast-only", action="store_true",
        help="동적 분석만 수행 (SAST 건너뜀)",
    )
    p.add_argument(
        "--endpoint", metavar="PATH", action="append", dest="endpoints",
        help="DAST 대상 엔드포인트를 직접 지정 (여러 번 사용 가능). "
             "미지정 시 코드에서 자동 추출",
    )
    return p


# 유틸리티
def _banner():
    print("\n" + "=" * 68)
    print("  웹훅 핸들러 보안 취약점 자동 탐지 프레임워크")
    print("=" * 68)


def _section(title: str):
    print(f"\n{'─' * 68}")
    print(f"  {title}")
    print(f"{'─' * 68}")


def _ok(msg: str):
    print(f"  ✓ {msg}")


def _warn(msg: str):
    print(f"  △ {msg}")


def _err(msg: str):
    print(f"  ✗ {msg}", file=sys.stderr)


# 메인 파이프라인
def run(args: argparse.Namespace) -> int:
    """
    전체 파이프라인 실행.
    반환값: 0 = 취약점 없음, 1 = 취약점 발견, 2 = 입력 오류
    """
    _banner()
    t_start = time.time()

    # 입력 검증 
    if not os.path.isfile(args.code):
        _err(f"파일을 찾을 수 없습니다: {args.code}")
        return 2
    # 두 플래그 동시 사용 차단
    if args.sast_only and args.dast_only:
        _err("--sast-only와 --dast-only를 동시에 사용할 수 없습니다.")
        return 2

    if not args.sast_only and not args.url:
        _err("DAST를 실행하려면 --url 이 필요합니다. (정적 분석만 하려면 --sast-only 사용)")
        return 2

    print(f"\n  대상 파일 : {args.code}")
    if args.url:
        print(f"  서버 URL  : {args.url}")
    print(f"  시크릿    : {'(미입력)' if not args.secret else '*' * min(len(args.secret), 8) + f' (길이 {len(args.secret)})'}")
    print(f"  상태 생성 : {args.state_create}")
    print(f"  상태 조회 : {args.state_query}")

    # [1] AST 파싱
    _section("[1] 코드 파싱")
    engine = WebhookASTEngine()
    try:
        pr = engine.parse_file(args.code)
    except Exception as e:
        _err(f"파싱 실패: {e}")
        return 2

    if pr.errors:
        for err in pr.errors:
            _err(err)
        return 2

    _ok(f"핸들러 {len(pr.handlers)}개 발견")
    for h in pr.handlers:
        print(f"     {h.http_method.upper():5s} {h.route_path} → {h.name}()")

    if not pr.handlers:
        _warn("웹훅 핸들러가 없습니다. 경로에 webhook/hook/callback/notify/event 키워드가 있는지 확인하세요.")

    # [2] 플랫폼 감지
    _section("[2] 플랫폼 감지")
    sig_format = None
    if _PLATFORM_AVAILABLE:
        detector = PlatformDetector()
        det_result = detector.detect(pr)
        print(f"  플랫폼   : {det_result.platform.value} (신뢰도: {det_result.confidence})")
        print(f"  서명 헤더: {det_result.sig_format.sig_header}")
        print(f"  알고리즘 : {det_result.sig_format.algo}")
        print(f"  Tier 예측: {det_result.sig_format.predicted_tier_hint}")
        for ev in det_result.evidence:
            print(f"  근거     : {ev}")
        sig_format = det_result.sig_format
    else:
        _warn("platform.py를 찾을 수 없습니다. 기본 서명 형식(X-Hub-Signature-256)으로 진행합니다.")

    # [3] 정적 분석 (SAST)
    sast_findings = []
    if not args.dast_only:
        _section("[3] 정적 분석 (SAST)")
        sast = SASTEngine()
        sast_findings = sast.analyze(pr)
        if sast_findings:
            print(f"  탐지: {len(sast_findings)}건")
            for f in sast_findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                        "LOW": "🟢", "INFO": "⚪"}.get(f.severity.value, "")
                print(f"  {icon} {f.rule_id} {f.severity.value:8s} "
                      f"L{f.lineno:3d} | {f.handler_name:28s} | {f.message[:55]}")
        else:
            _ok("SAST 취약점 없음")
    else:
        _warn("--dast-only 옵션: SAST 건너뜀")

    # [4] 동적 분석 (DAST)
    probes = {}       # path → ProbeResult
    all_attacks = {}  # path → List[AttackResult]
    all_endpoint_paths = []

    if not args.sast_only and args.url:
        _section("[4] 동적 분석 (DAST)")

        # 서명 헤더 결정
        if sig_format:
            sig_header = sig_format.sig_header
        else:
            sig_header = "X-Hub-Signature-256"

        # DAST 설정
        cfg = DastConfig(
            base_url=args.url.rstrip("/"),
            secret=args.secret.encode() if args.secret else b"",
            timeout=args.timeout,
            state_create_path=args.state_create,
            state_query_template=args.state_query,
            # 버그 20 수정: 플랫폼 감지 결과를 DastConfig에 전달
            sig_header=sig_format.sig_header if sig_format else "X-Hub-Signature-256",
            is_stripe=sig_format.is_stripe if sig_format else False,
            is_slack=sig_format.is_slack if sig_format else False,
            platform_name=sig_format.platform.value if sig_format else "generic",
        )
        dast = DASTEngine(cfg)

        # 대상 엔드포인트 결정
        if args.endpoints:
            # 사용자가 직접 지정
            target_paths = args.endpoints
            _ok(f"사용자 지정 엔드포인트: {target_paths}")
        else:
            # 코드에서 자동 추출 (웹훅 경로만)
            target_paths = [
                r.path for r in pr.routes if r.is_webhook
            ]
            if not target_paths:
                # is_webhook이 아닌 경로도 포함 시도
                target_paths = [r.path for r in pr.routes]
            _ok(f"코드에서 추출한 엔드포인트: {target_paths}")

        if not target_paths:
            _warn("분석할 엔드포인트를 찾지 못했습니다. --endpoint 옵션으로 직접 지정하세요.")
        else:
            # Probe → Tier 결정
            print(f"\n  Probe (Tier 분류):")
            for path in target_paths:
                probe = dast.probe(path, sig_header)
                probes[path] = probe
                tier_icon = {"Tier 1": "🟢", "Tier 2": "🟡"}.get(
                    probe.tier.value, ""
                )
                flag = " ⚠ 서명없이수락" if probe.step1_accepted else ""
                print(f"  {tier_icon} {probe.tier.value}  {path:35s}"
                      f"  1:{probe.step1_code}{flag}  2:{probe.step2_code}"
                      f"  3:{probe.step3_code}  상태:{'✓' if probe.step4_state_ok else '✗'}")

            # 공격 실행
            print(f"\n  공격 (다운그레이드 + 재전송 + 타입혼동):")
            for path in target_paths:
                probe = probes[path]
                attacks = dast.run_all(path, probe)
                all_attacks[path] = attacks
                vulns = [a for a in attacks if a.vulnerable]
                if vulns:
                    for a in vulns:
                        print(f"  🔴 {path:35s}  {a.attack_type.value:16s}"
                              f"  {a.confidence.value:6s} | {a.description[:50]}")
                        for detail in a.details:
                            print(f"       {detail}")
                else:
                    print(f"  🟢 {path:35s}  전 공격 거부")

            all_endpoint_paths = target_paths
    else:
        if args.sast_only:
            _warn("--sast-only 옵션: DAST 건너뜀")

    # [5] 통합 리포트 생성
    _section("[5] 통합 리포트")

    # 핸들러 이름 → 경로 매핑
    handler_to_path = {
        r.function_name: r.path
        for r in pr.routes
        if r.is_webhook
    }
    # is_webhook이 아닌 경우도 포함
    for r in pr.routes:
        if r.function_name not in handler_to_path:
            handler_to_path[r.function_name] = r.path

    # 엔드포인트별 SAST Finding 그룹핑
    ep_sast: dict = {ep: [] for ep in all_endpoint_paths}
    unmatched_sast = []
    for f in sast_findings:
        path = handler_to_path.get(f.handler_name)
        if path and path in ep_sast:
            ep_sast[path].append(f)
        else:
            unmatched_sast.append(f)

    # 매핑되지 않은 Finding을 첫 번째 엔드포인트에 fallback 추가하여 누락 방지
    if unmatched_sast and ep_sast:
        first_ep = next(iter(ep_sast))
        for f in unmatched_sast:
            ep_sast[first_ep].append(f)

    # SAST only 모드에서는 경로별로 가상의 엔드포인트 리포트 생성
    if args.sast_only or not all_endpoint_paths:
        ep_reports = []
        seen_paths = set()
        # 모듈 레벨 Finding(WHSEC-DYN)은 handler_name이 "(모듈 레벨)" 또는 "(파일 전체)"이므로
        # 핸들러 이름 필터에서 누락됨 → 별도로 수집하여 첫 번째 핸들러에만 포함
        MODULE_LEVEL_NAMES = {"(모듈 레벨)", "(파일 전체)"}
        module_findings = [
            f for f in sast_findings
            if f.handler_name in MODULE_LEVEL_NAMES
        ]
        module_assigned = False
        for h in pr.handlers:
            path = h.route_path
            if path in seen_paths:
                continue
            seen_paths.add(path)
            h_findings = [f for f in sast_findings if f.handler_name == h.name]
            # 첫 번째 핸들러에 모듈 레벨 Finding 포함
            if not module_assigned:
                h_findings = h_findings + module_findings
                module_assigned = True
            er = compute_endpoint_report(
                path=path,
                tier=Tier.TIER_2,
                sast_findings=h_findings,
                dast_results=[],
            )
            ep_reports.append(er)
    else:
        ep_reports = []
        for path in all_endpoint_paths:
            probe = probes.get(path)
            tier = probe.tier if probe else Tier.TIER_2
            er = compute_endpoint_report(
                path=path,
                tier=tier,
                sast_findings=ep_sast.get(path, []),
                dast_results=all_attacks.get(path, []),
            )
            ep_reports.append(er)

    full = compute_full_report(
        target_file=os.path.basename(args.code),
        endpoint_reports=ep_reports,
    )
    print_report(full)

    elapsed = time.time() - t_start
    print(f"  분석 소요 시간: {elapsed:.1f}초\n")

    # 종료 코드: 취약점 있으면 1
    has_vuln = full.total_sast_findings > 0 or full.total_dast_vulns > 0
    return 1 if has_vuln else 0


# 진입점
def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
