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
import tokenize

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzer.engine import WebhookASTEngine
from analyzer.sast import SASTEngine
from analyzer.dast import DASTEngine, DastConfig, Tier
from analyzer.report import compute_endpoint_report, compute_full_report, group_findings
from analyzer.serializer import full_report_to_dict, probe_result_to_dict
from backend.upload import process_upload, find_webhook_files, cleanup, UploadError, MAX_FILE_SIZE

try:
    from analyzer.platform import PlatformDetector, Platform, PLATFORM_DOC_LINKS
    _PLATFORM_AVAILABLE = True
except ImportError:
    _PLATFORM_AVAILABLE = False
    PLATFORM_DOC_LINKS = {}


app = FastAPI(
    title="HookLens",
    description="웹훅 핸들러 보안 취약점 자동 탐지 프레임워크",
    version="2.1.0",
)


def _attach_source_context(endpoints, project_root):
    """Add bounded display excerpts before upload cleanup; detection is unchanged."""
    root = os.path.realpath(project_root)
    cache = {}
    for endpoint in endpoints:
        for finding in endpoint.get("sast_findings", []):
            path = os.path.realpath(finding.get("filepath", ""))
            try:
                if os.path.commonpath([root, path]) != root:
                    continue
                line = int(finding.get("lineno", 0))
                if line < 1:
                    continue
                if path not in cache:
                    with tokenize.open(path) as source:
                        cache[path] = source.read().splitlines()
                lines = cache[path]
                if line > len(lines):
                    continue
                start = max(0, line - 4)
                finding["display_path"] = os.path.relpath(path, root).replace(os.sep, "/")
                finding["source_context"] = {
                    "start_line": start + 1,
                    "lines": [text[:1000] for text in lines[start:line + 3]],
                }
            except (OSError, ValueError, TypeError, SyntaxError, UnicodeError):
                continue


@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = os.path.join(_ROOT, "frontend", "index.html")
    if not os.path.isfile(html_path):
        return HTMLResponse("<h1>frontend/index.html 을 찾을 수 없습니다.</h1>", status_code=404)
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.1.0", "platform_detector": _PLATFORM_AVAILABLE}


@app.post("/analyze")
async def analyze(
    code: UploadFile = File(..., description=".py 또는 .zip 파일"),
    webhook_url: str = Form("", description="웹훅 수신 서버 base URL (DAST용). 비워두면 SAST만 실행"),
    state_create: str = Form("", description="[Tier 1] 상태 생성 경로 (선택)"),
    state_query: str = Form("", description="[Tier 1] 상태 조회 경로 템플릿 (선택)"),
    secret: str = Form("", description="HMAC 서명 시크릿 키 (선택 — 비우면 정상 서명 시험 생략)"),
    sast_only: bool = Form(False, description="True면 DAST 건너뜀"),
    strict_json: bool = Form(False, description="대상이 JSON 객체 전용 정책을 가진 경우에만 선택"),
    timestamp_tolerance: int = Form(300, ge=1, le=86400),
):
    t_start = time.time()
    tmp_dir = None
    dast_sessions = []
    parse_errors = []
    endpoint_detections = {}

    try:
        # 1) 파일 업로드 처리 
        file_bytes = await code.read(MAX_FILE_SIZE + 1)
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
                parse_errors.extend(f"{os.path.basename(fpath)}: {error}" for error in pr.errors)
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

        # 4) 엔드포인트별 플랫폼 설정으로 동일한 Probe → 공격 3종 수행
        probes, all_attacks = {}, {}
        all_endpoint_paths = list(dict.fromkeys(h.route_path for pr in handler_prs for h in pr.handlers))
        route_map = {r.path: r for pr in handler_prs for r in pr.routes if r.is_webhook}
        from collections import Counter
        path_counts = Counter(h.route_path for pr in handler_prs for h in pr.handlers)
        ambiguous_paths = {path for path, count in path_counts.items() if count > 1}
        if ambiguous_paths:
            parse_errors.append("중복 핸들러 경로 발견 — 라우터 등록 관계 확인 필요: " + ", ".join(sorted(ambiguous_paths)))
        if _PLATFORM_AVAILABLE:
            for pr in handler_prs:
                detections = PlatformDetector().detect_per_handler(pr)
                for h in pr.handlers:
                    endpoint_detections[h.route_path] = detections[h.name]
        run_dast = bool(webhook_url.strip()) and not sast_only
        if run_dast:
            from urllib.parse import urlsplit
            parsed = urlsplit(webhook_url.strip())
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise HTTPException(422, "웹훅 URL은 인증정보·쿼리·fragment 없는 HTTP(S) base URL이어야 합니다.")
            for path in all_endpoint_paths:
                det = endpoint_detections.get(path)
                fmt = det.sig_format if det else None
                cfg = DastConfig(base_url=webhook_url.strip().rstrip("/"),
                    secret=secret.encode() if secret else b"", timeout=5.0,
                    state_create_path=state_create.strip(), state_query_template=state_query.strip(),
                    sig_header=fmt.sig_header if fmt else sig_header,
                    is_stripe=fmt.is_stripe if fmt else False, is_slack=fmt.is_slack if fmt else False,
                    platform_name=det.platform.value if det else "generic",
                    strict_json=strict_json, timestamp_tolerance=timestamp_tolerance)
                dast = DASTEngine(cfg)
                dast_sessions.append(dast)
                route = route_map[path]
                if path in ambiguous_paths or route.method != "POST" or route.path_params:
                    from analyzer.dast import ProbeResult
                    probe = ProbeResult(endpoint=path, validation_error="중복 경로, POST 이외 메서드 또는 미치환 경로 파라미터는 자동 시험 불가")
                else:
                    probe = dast.probe(path)
                probes[path] = probe
                all_attacks[path] = dast.run_all(path, probe)

        # 5) 위치가 다른 외부 위임 Finding도 원래 핸들러에 연결한다.
        ep_sast = group_findings(all_parse_results, all_sast_findings)
        ep_reports = [compute_endpoint_report(path,
                         probes[path].tier if path in probes else Tier.TIER_2,
                         ep_sast.get(path, []), all_attacks.get(path, []))
                      for path in all_endpoint_paths]

        full = compute_full_report(target_file=filename, endpoint_reports=ep_reports)

        if parse_errors or has_router_split:
            full.analysis_status = "partial"
            if full.overall_grade.startswith("A"):
                full.overall_grade = "N/A — 파싱/라우터 경로 추가 확인 필요"

        # 6) 응답
        result = full_report_to_dict(full)
        result["elapsed_sec"]       = round(time.time() - t_start, 2)
        result["platform"]          = platform_info
        result["platform_doc"]      = doc_links   # 공식 문서 링크
        result["dast_ran"]          = run_dast
        result["files_analyzed"]    = [os.path.basename(p) for p in py_files]
        result["analysis_warnings"] = parse_errors + (["라우터 prefix/등록 관계는 자동 합성하지 않음; 실제 경로를 확인하세요."] if has_router_split else [])
        for endpoint in result["endpoints"]:
            path = endpoint["path"]
            if path in probes:
                endpoint["probe"] = probe_result_to_dict(probes[path])
            if path in endpoint_detections:
                det = endpoint_detections[path]
                endpoint["platform"] = {"platform": det.platform.value, "sig_header": det.sig_format.sig_header, "confidence": det.confidence}
        result["has_router_split"]  = has_router_split  # include_router 경고
        _attach_source_context(result["endpoints"], tmp_dir)

        # DAST 연결 오류가 있으면 warnings에 포함
        dast_warnings = []
        for path, probe in probes.items():
            if probe.connection_error:
                dast_warnings.append(f"{path}: {probe.connection_error}")
        if dast_warnings:
            result["dast_warnings"] = dast_warnings

        return JSONResponse(result)

    finally:
        for session in dast_sessions:
            session.close()
        if tmp_dir:
            cleanup(tmp_dir)
