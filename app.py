"""
app.py

FastAPI 기반 웹훅 보안 분석 API 서버.
engine.parse_file()에 project_root를 전달하여 중첩 import 추적을 지원하며,
DastConfig에 platform_name을 전달해 플랫폼별 mock payload를 생성한다.
include_router 감지 시 경고 메시지를 응답에 포함한다.
"""

import os
import sys
import time

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzer.engine import WebhookASTEngine
from analyzer.sast import SASTEngine
from analyzer.dast import DASTEngine, DastConfig, Tier
from analyzer.report import compute_endpoint_report, compute_full_report
from analyzer.serializer import full_report_to_dict
from backend.upload import process_upload, find_webhook_files, cleanup, UploadError

try:
    from analyzer.platform import PlatformDetector, Platform, PLATFORM_DOC_LINKS
    _PLATFORM_AVAILABLE = True
except ImportError:
    _PLATFORM_AVAILABLE = False
    PLATFORM_DOC_LINKS = {}


app = FastAPI(
    title="Webhook Security Analyzer",
    description="웹훅 핸들러 보안 취약점 자동 탐지 프레임워크",
    version="2.0.0",
)


@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = os.path.join(_ROOT, "frontend", "index.html")
    if not os.path.isfile(html_path):
        return HTMLResponse("<h1>frontend/index.html 을 찾을 수 없습니다.</h1>", status_code=404)
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "platform_detector": _PLATFORM_AVAILABLE}


@app.post("/analyze")
async def analyze(
    code: UploadFile = File(..., description=".py 또는 .zip 파일"),
    webhook_url: str = Form("", description="웹훅 수신 서버 base URL (DAST용). 비워두면 SAST만 실행"),
    state_create: str = Form("", description="[Tier 1] 상태 생성 경로 (선택)"),
    state_query: str = Form("", description="[Tier 1] 상태 조회 경로 템플릿 (선택)"),
    secret: str = Form("", description="HMAC 서명 시크릿 키 (선택 — 비우면 재전송 공격 생략)"),
    sast_only: bool = Form(False, description="True면 DAST 건너뜀"),
):
    t_start = time.time()
    tmp_dir = None

    try:
        # 1) 파일 업로드 처리 
        file_bytes = await code.read()
        filename = code.filename or "upload.py"

        try:
            tmp_dir, py_files = process_upload(file_bytes, filename)
        except UploadError as e:
            raise HTTPException(status_code=400, detail=str(e))

        py_files = find_webhook_files(py_files)

        # 2) AST 파싱 + SAST
        ast_engine = WebhookASTEngine()
        sast_engine = SASTEngine()

        all_parse_results = []
        all_sast_findings = []
        has_router_split = False

        for fpath in py_files:
            # project_root=tmp_dir 전달
            # from app.core.security import verify_sig 같은 중첩 import도 tmp_dir 기준으로 파일을 찾아감
            pr = ast_engine.parse_file(fpath, project_root=tmp_dir)
            if pr.errors:
                continue
            all_parse_results.append(pr)
            all_sast_findings.extend(sast_engine.analyze(pr))
            if pr.has_router_split:
                has_router_split = True

        if not all_parse_results:
            raise HTTPException(
                status_code=422,
                detail="업로드된 파일에서 파싱 가능한 Python 코드를 찾지 못했습니다.",
            )

        handler_prs = [pr for pr in all_parse_results if pr.handlers]
        if not handler_prs:
            result = {
                "target_file": filename,
                "overall_grade": "N/A — 웹훅 핸들러 없음",
                "total_sast_findings": len(all_sast_findings),
                "total_dast_vulns": 0,
                "endpoints": [],
                "warning": "webhook/hook/callback 경로 핸들러를 찾지 못했습니다.",
                "has_router_split": has_router_split,
                "elapsed_sec": round(time.time() - t_start, 2),
            }
            return JSONResponse(result)

        main_pr = max(handler_prs, key=lambda p: len(p.handlers))

        # 3) 플랫폼 감지
        sig_header = "X-Hub-Signature-256"
        is_stripe = False
        is_slack = False
        platform_name = "generic"
        platform_info = {}
        doc_links = {}

        if _PLATFORM_AVAILABLE:
            detector = PlatformDetector()
            det = detector.detect(main_pr)
            sig_header   = det.sig_format.sig_header
            is_stripe    = det.sig_format.is_stripe
            is_slack     = det.sig_format.is_slack
            platform_name = det.platform.value
            platform_info = {
                "platform":   det.platform.value,
                "confidence": det.confidence,
                "sig_header": sig_header,
                "algo":       det.sig_format.algo,
                "tier_hint":  det.sig_format.predicted_tier_hint,
                "evidence":   det.evidence,
            }
            # 플랫폼별 공식 문서 링크
            if det.platform in PLATFORM_DOC_LINKS:
                doc_links = PLATFORM_DOC_LINKS[det.platform]

        # 4) DAST
        probes = {}
        all_attacks = {}
        all_endpoint_paths = []
        run_dast = bool(webhook_url.strip()) and not sast_only

        if run_dast:
            cfg = DastConfig(
                base_url=webhook_url.rstrip("/"),
                secret=secret.encode() if secret.strip() else b"",
                timeout=5.0,
                state_create_path=state_create.strip(),
                state_query_template=state_query.strip(),
                sig_header=sig_header,
                is_stripe=is_stripe,
                is_slack=is_slack,
                platform_name=platform_name,
            )
            dast = DASTEngine(cfg)

            for pr in handler_prs:
                for route in pr.routes:
                    if route.is_webhook and route.path not in all_endpoint_paths:
                        all_endpoint_paths.append(route.path)

            for path in all_endpoint_paths:
                probe = dast.probe(path, sig_header)
                probes[path] = probe
                attacks = dast.run_all(path, probe)
                all_attacks[path] = attacks

        # 5) 리포트 생성
        # 다중 파일 업로드 시 동일 함수명 충돌을 방지하기 위해 (filepath, function_name) 튜플을 키로 사용
        # SAST Finding의 handler_name 매핑은 filepath도 함께 고려
        handler_to_path = {}
        for pr in all_parse_results:
            for route in pr.routes:
                # 파일 경로를 포함한 고유 키로 저장 (충돌 방지)
                handler_to_path[(pr.filepath, route.function_name)] = route.path
                # handler_name만으로도 찾을 수 있도록 미충돌 시 단순 키도 등록
                if route.function_name not in handler_to_path:
                    handler_to_path[route.function_name] = route.path

        def _find_path(finding):
            """Finding의 filepath + handler_name 조합으로 경로 탐색"""
            # 1순위: (filepath, handler_name) 정확한 매핑
            p = handler_to_path.get((finding.filepath, finding.handler_name))
            if p:
                return p
            # 2순위: handler_name만으로 탐색 (단일 파일 업로드 등 기존 호환)
            return handler_to_path.get(finding.handler_name)

        ep_sast: dict = {ep: [] for ep in all_endpoint_paths}
        for f in all_sast_findings:
            path = _find_path(f)
            if path and path in ep_sast:
                ep_sast[path].append(f)

        # 모듈 레벨 Finding(WHSEC-DYN)은 handler_name이 "(모듈 레벨)" 또는 "(파일 전체)"이므로
        # 핸들러 이름 매핑에서 누락됨 → 별도로 수집하여 해당 파일의 첫 번째 핸들러 경로에 포함
        MODULE_LEVEL_NAMES = {"(모듈 레벨)", "(파일 전체)"}

        # DAST 실행 여부와 무관하게 모듈 레벨 Finding을 ep_sast에 fallback 추가
        # (SAST-only 분기에서도, DAST 분기에서도 ep_sast를 공통으로 참조하므로 여기서 처리)
        if all_endpoint_paths:
            unmatched_module = [
                f for f in all_sast_findings
                if f.handler_name in MODULE_LEVEL_NAMES
            ]
            if unmatched_module:
                first_ep = all_endpoint_paths[0]
                ep_sast[first_ep].extend(unmatched_module)

        if not run_dast:
            ep_reports = []
            seen = set()
            for pr in handler_prs:
                # 이 파일에서 발생한 모듈 레벨 Finding 수집
                module_findings = [
                    f for f in all_sast_findings
                    if f.handler_name in MODULE_LEVEL_NAMES
                    and f.filepath == pr.filepath
                ]
                module_assigned = False  # 파일당 첫 핸들러에만 한 번 포함
                for h in pr.handlers:
                    if h.route_path in seen:
                        continue
                    seen.add(h.route_path)
                    h_findings = [
                        f for f in all_sast_findings
                        if f.handler_name == h.name
                        and f.filepath == pr.filepath  # 파일 경로도 함께 확인하여 동일 함수명 충돌 방지
                    ]
                    # 첫 번째 핸들러에 모듈 레벨 Finding 포함
                    if not module_assigned:
                        h_findings = h_findings + module_findings
                        module_assigned = True
                    ep_reports.append(compute_endpoint_report(
                        path=h.route_path,
                        tier=Tier.TIER_2,
                        sast_findings=h_findings,
                        dast_results=[],
                    ))
        else:
            ep_reports = []
            for path in all_endpoint_paths:
                probe = probes.get(path)
                tier = probe.tier if probe else Tier.TIER_2
                ep_reports.append(compute_endpoint_report(
                    path=path,
                    tier=tier,
                    sast_findings=ep_sast.get(path, []),
                    dast_results=all_attacks.get(path, []),
                ))

        full = compute_full_report(target_file=filename, endpoint_reports=ep_reports)

        # 6) 응답
        result = full_report_to_dict(full)
        result["elapsed_sec"]       = round(time.time() - t_start, 2)
        result["platform"]          = platform_info
        result["platform_doc"]      = doc_links   # 공식 문서 링크
        result["dast_ran"]          = run_dast
        result["files_analyzed"]    = [os.path.basename(p) for p in py_files]
        result["has_router_split"]  = has_router_split  # include_router 경고

        # DAST 연결 오류가 있으면 warnings에 포함
        dast_warnings = []
        for path, probe in probes.items():
            if probe.connection_error:
                dast_warnings.append(f"{path}: {probe.connection_error}")
        if dast_warnings:
            result["dast_warnings"] = dast_warnings

        return JSONResponse(result)

    finally:
        if tmp_dir:
            cleanup(tmp_dir)
