"""
analyzer/sast.py

정적 분석(SAST) — 5개 규칙 통합 + 수정 코드 스니펫
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

규칙 목록:
  WHSEC-001  서명 검증 누락         [V1]  CRITICAL
  WHSEC-002  타이밍 공격 (==비교)   [V2]  HIGH
  WHSEC-003  취약한 해시 알고리즘   [V3]  MEDIUM/CRITICAL
  WHSEC-004  타임스탬프 검증 누락   [V4]  MEDIUM
  WHSEC-005  외부 파일 위임 결함    [V5]  MEDIUM/CRITICAL

각 규칙은 Finding + 자동 수정 코드 스니펫(fix_snippet)을 생성합니다.
Tier에 따라 SAST 동작 자체는 달라지지 않습니다 (SAST는 소스코드 기반).
"""
import ast
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set

from analyzer.engine import (
    WebhookHandler, FunctionInfo, ParseResult, WebhookASTEngine,
    collect_calls, collect_comparisons, get_call_name, called_function_names,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 데이터 구조
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    filepath: str
    handler_name: str
    lineno: int
    end_lineno: Optional[int] = None
    cvss_score: float = 0.0
    recommendation: str = ""
    fix_snippet: str = ""       # ← 자동 수정 코드 스니펫
    code_snippet: str = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 상수
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERIFY_CALL_PATTERNS = {"hmac.new", "hmac.compare_digest", "hmac.digest"}
VERIFY_NAME_KEYWORDS = {"verify", "validate", "check_sig", "check_signature"}
SIG_VAR_KEYWORDS = {"sig", "signature", "hash", "computed", "expected",
                     "digest", "hmac", "x_hub_signature", "x_signature",
                     "stripe_signature"}
WEAK_ALGORITHMS = {"sha1", "md5"}
TIMESTAMP_KEYWORDS = {"timestamp", "time", "ts", "nonce", "expires"}
# 버그 8 수정: 문자열 상수 검색 시 오탐 방지를 위해 명확한 타임스탬프 헤더명만 허용
# "time", "ts" 같은 짧은 단어는 부분 매칭으로 오탐 발생 가능 ("X-Request-Timeout" 등)
TIMESTAMP_HEADER_STRINGS = {
    "x-timestamp",
    "x-slack-request-timestamp",
    "stripe-timestamp",
    "toss-timestamp",
    "x-request-timestamp",
}
TIME_CALL_PATTERNS = {"time.time", "datetime.now", "datetime.utcnow"}
SKIP_MODULES = {"fastapi", "flask", "django", "starlette", "pydantic",
                "hashlib", "hmac", "json", "os", "sys", "time", "datetime",
                "typing", "logging", "stripe", "requests", "httpx", "aiohttp"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 수정 코드 스니펫 템플릿
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FIX_SNIPPETS = {
    "WHSEC-001": '''\
# ── 수정: 서명 검증 추가 ──
import hmac, hashlib, os
from fastapi import Request, HTTPException, Header

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()

@app.post("{route}")
async def {func}(
    request: Request,
    x_hub_signature_256: str = Header(None),
):
    payload = await request.body()
    if x_hub_signature_256 is None:
        raise HTTPException(401, "Missing signature")
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET, payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hub_signature_256, expected):
        raise HTTPException(401, "Invalid signature")
    data = await request.json()
    # ... 안전하게 처리 ...
    return {{"status": "ok"}}
''',

    "WHSEC-002": '''\
# ── 수정: == 대신 hmac.compare_digest 사용 ──
# 변경 전 (취약):
#   if signature == computed:
# 변경 후 (안전):
if hmac.compare_digest(signature, computed):
    # 서명 일치 — 처리 진행
    pass
''',

    "WHSEC-003-sha1": '''\
# ── 수정: SHA1 → SHA256 교체 ──
# 변경 전 (취약):
#   computed = hmac.new(secret, payload, hashlib.sha1).hexdigest()
# 변경 후 (안전):
computed = "sha256=" + hmac.new(
    secret, payload, hashlib.sha256
).hexdigest()
''',

    "WHSEC-003-md5": '''\
# ── 수정: MD5 → SHA256 교체 ──
# 변경 전 (취약):
#   computed = hmac.new(secret, payload, hashlib.md5).hexdigest()
# 변경 후 (안전):
computed = "sha256=" + hmac.new(
    secret, payload, hashlib.sha256
).hexdigest()
''',

    "WHSEC-004": '''\
# ── 수정: 타임스탬프 검증 추가 ──
import time

TIMESTAMP_TOLERANCE = 300  # 5분

def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    return abs(time.time() - ts) <= TIMESTAMP_TOLERANCE

# 핸들러 내부에서:
x_timestamp = request.headers.get("X-Timestamp")
if not x_timestamp or not verify_timestamp(x_timestamp):
    raise HTTPException(401, "Timestamp expired or invalid")
''',

    "WHSEC-005": '''\
# ── 수정: 위임 함수 내부 == → compare_digest 교체 ──
# 파일: {module}.py
def {func}(signature: str, payload: bytes, secret: bytes) -> bool:
    computed = "sha256=" + hmac.new(
        secret, payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, computed)  # 상수 시간 비교
''',
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SAST 엔진
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class SASTEngine:
    """정적 분석 5개 규칙 통합 실행"""

    def __init__(self):
        self._ast_engine = WebhookASTEngine()

    def analyze_file(self, filepath: str) -> List[Finding]:
        pr = self._ast_engine.parse_file(filepath)
        return self.analyze(pr)

    def analyze(self, pr: ParseResult) -> List[Finding]:
        findings = []

        # ── 파일 단위 사전 점검 ──

        # 피드백 4: 동적 import(importlib) 감지 → INFO Finding 생성
        # AST 정적 분석은 런타임에 결정되는 import를 추적할 수 없으므로
        # 발견 즉시 "DAST로 검증 대체" 안내를 리포트에 표시합니다.
        dynamic_imports = self._ast_engine.detect_dynamic_imports(pr.tree)
        for name, lineno in dynamic_imports:
            findings.append(Finding(
                rule_id="WHSEC-DYN",
                rule_name="동적 임포트 감지",
                severity=Severity.INFO,
                message=f"동적 임포트({name}) 감지됨 — 정적 추적 불가. DAST 동적 분석으로 검증을 대체합니다.",
                filepath=pr.filepath,
                handler_name="(파일 전체)",
                lineno=lineno,
                cvss_score=0.0,
                recommendation="importlib 사용 시 정적 분석 범위를 벗어납니다. DAST 결과를 우선 참고하세요.",
            ))

        # 핸들러별 규칙 적용
        for handler in pr.handlers:
            findings.extend(self._rule_01(handler, pr))
            findings.extend(self._rule_02(handler, pr))
            findings.extend(self._rule_03(handler, pr))
            findings.extend(self._rule_04(handler, pr))
            findings.extend(self._rule_05(handler, pr))
        return findings

    # ──────────────────────────────────────────────────────
    # WHSEC-001: 서명 검증 누락
    # ──────────────────────────────────────────────────────
    def _rule_01(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        calls = [c[0] for c in collect_calls(h.ast_node)]
        if self._has_verify(calls):
            return []

        for name in called_function_names(h.ast_node):
            if name in pr.functions:
                inner = [c[0] for c in collect_calls(pr.functions[name].ast_node)]
                if self._has_verify(inner):
                    return []
            if any(kw in name.lower() for kw in VERIFY_NAME_KEYWORDS):
                return []

        for imp in pr.imports:
            alias = imp.alias or imp.name
            if alias in called_function_names(h.ast_node):
                if any(kw in imp.name.lower() for kw in VERIFY_NAME_KEYWORDS):
                    return []

        fix = FIX_SNIPPETS["WHSEC-001"].format(route=h.route_path, func=h.name)
        return [Finding(
            rule_id="WHSEC-001",
            rule_name="서명 검증 누락",
            severity=Severity.CRITICAL,
            message=f"핸들러 '{h.name}' ({h.route_path})에 서명 검증이 없습니다.",
            filepath=pr.filepath, handler_name=h.name,
            lineno=h.lineno, end_lineno=h.end_lineno,
            cvss_score=9.8,
            recommendation="HMAC-SHA256 서명 검증을 추가하세요.",
            fix_snippet=fix,
            code_snippet=h.source_code[:300],
        )]

    # ──────────────────────────────────────────────────────
    # WHSEC-002: 타이밍 공격 (== 비교)
    # ──────────────────────────────────────────────────────
    def _rule_02(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        findings = []
        findings.extend(self._check_eq(h.ast_node, h, pr, ""))
        for name in called_function_names(h.ast_node):
            if name in pr.functions:
                findings.extend(self._check_eq(
                    pr.functions[name].ast_node, h, pr, name))
        return findings

    def _check_eq(self, node, h, pr, delegated):
        findings = []
        for cmp in collect_comparisons(node):
            for op in cmp.ops:
                if not isinstance(op, (ast.Eq, ast.NotEq)):
                    continue
                ops = [cmp.left] + cmp.comparators
                if any(isinstance(o, ast.Name) and
                       any(kw in o.id.lower() for kw in SIG_VAR_KEYWORDS)
                       for o in ops):
                    loc = f" (위임: {delegated})" if delegated else ""
                    findings.append(Finding(
                        rule_id="WHSEC-002",
                        rule_name="타이밍 공격 취약 비교",
                        severity=Severity.HIGH,
                        message=f"핸들러 '{h.name}'{loc}에서 서명을 == 비교합니다.",
                        filepath=pr.filepath, handler_name=h.name,
                        lineno=getattr(cmp, "lineno", h.lineno),
                        cvss_score=7.4,
                        fix_snippet=FIX_SNIPPETS["WHSEC-002"],
                    ))
        return findings

    # ──────────────────────────────────────────────────────
    # WHSEC-003: 취약한 해시 알고리즘
    # ──────────────────────────────────────────────────────
    def _rule_03(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        findings = []
        findings.extend(self._check_hash(h.ast_node, h, pr, ""))
        for name in called_function_names(h.ast_node):
            if name in pr.functions:
                findings.extend(self._check_hash(
                    pr.functions[name].ast_node, h, pr, name))
        return findings

    def _check_hash(self, node, h, pr, delegated):
        findings = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            cn = get_call_name(child)
            if cn == "hmac.new" and len(child.args) >= 3:
                algo = self._extract_algo(child.args[2])
                if algo in WEAK_ALGORITHMS:
                    sev = Severity.CRITICAL if algo == "md5" else Severity.MEDIUM
                    score = 9.1 if algo == "md5" else 6.5
                    desc = ("MD5는 암호학적으로 완전히 파기됨" if algo == "md5"
                            else "SHA1은 충돌 공격이 실증됨")
                    loc = f" (위임: {delegated})" if delegated else ""
                    fix_key = f"WHSEC-003-{algo}"
                    findings.append(Finding(
                        rule_id="WHSEC-003",
                        rule_name="취약한 해시 알고리즘",
                        severity=sev,
                        message=f"핸들러 '{h.name}'{loc}: "
                                f"HMAC에 {algo.upper()} 사용. {desc}.",
                        filepath=pr.filepath, handler_name=h.name,
                        lineno=getattr(child, "lineno", h.lineno),
                        cvss_score=score,
                        recommendation=f"hashlib.{algo} → hashlib.sha256",
                        fix_snippet=FIX_SNIPPETS.get(fix_key, ""),
                    ))
        return findings

    def _extract_algo(self, node):
        # 기존: hashlib.md5 형태 (ast.Attribute)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "hashlib" and node.attr in WEAK_ALGORITHMS:
                return node.attr
        # 버그 2 수정: from hashlib import md5 후 md5 직접 사용 형태 (ast.Name)
        # 예) hmac.new(secret, payload, md5)  →  ast.Name(id='md5')
        if isinstance(node, ast.Name) and node.id in WEAK_ALGORITHMS:
            return node.id
        return ""

    # ──────────────────────────────────────────────────────
    # WHSEC-004: 타임스탬프 검증 누락
    # ──────────────────────────────────────────────────────
    def _rule_04(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        if not self._handler_has_sig(h, pr):
            return []
        if not self._has_ts_param(h.ast_node):
            return []
        if self._has_ts_check(h, pr):
            return []

        return [Finding(
            rule_id="WHSEC-004",
            rule_name="타임스탬프 검증 누락",
            severity=Severity.MEDIUM,
            message=f"핸들러 '{h.name}' ({h.route_path}): "
                    f"타임스탬프를 받지만 검증하지 않음. 재전송 공격에 취약.",
            filepath=pr.filepath, handler_name=h.name,
            lineno=h.lineno, end_lineno=h.end_lineno,
            cvss_score=5.9,
            recommendation="time.time()과 비교하여 ±5분 이내인지 검증하세요.",
            fix_snippet=FIX_SNIPPETS["WHSEC-004"],
        )]

    def _handler_has_sig(self, h, pr):
        for name, _ in collect_calls(h.ast_node):
            if "hmac" in name.lower() or "verify" in name.lower():
                return True
            if name in pr.functions:
                for iname, _ in collect_calls(pr.functions[name].ast_node):
                    if "hmac" in iname.lower():
                        return True
        return False

    def _has_ts_param(self, node):
        # 함수 파라미터 이름에서 검색 (TIMESTAMP_KEYWORDS 부분 매칭 허용)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args:
                if any(kw in arg.arg.lower() for kw in TIMESTAMP_KEYWORDS):
                    return True
        # 버그 8 수정: 문자열 상수 검색은 명확한 타임스탬프 헤더명으로만 제한
        # (포함 검색 → 정확한 매칭으로 변경하여 "X-Request-Timeout" 등 오탐 방지)
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value.lower() in TIMESTAMP_HEADER_STRINGS:
                    return True
        return False

    def _has_ts_check(self, h, pr):
        for cn, _ in collect_calls(h.ast_node):
            if cn in TIME_CALL_PATTERNS:
                return True
            if "timestamp" in cn.lower() and "verify" in cn.lower():
                return True
            if cn in pr.functions:
                for iname, _ in collect_calls(pr.functions[cn].ast_node):
                    if iname in TIME_CALL_PATTERNS:
                        return True
        return False

    # ──────────────────────────────────────────────────────
    # WHSEC-005: 외부 파일 위임 결함
    # ──────────────────────────────────────────────────────
    def _rule_05(self, h: WebhookHandler, pr: ParseResult,
                 _visited: Set[str] = None) -> List[Finding]:
        """
        외부 파일 위임 결함 탐지.

        _visited: 이미 탐색한 파일 경로 집합.
                  순환 참조(A→B→A) 발생 시 무한루프를 방지합니다.
                  최대 추적 깊이: 현재 파일 기준 1단계
                  (발표 방어 논리 "2단계까지만 추적" = 핸들러→외부파일 1단계)
        """
        if _visited is None:
            _visited = {pr.filepath}

        findings = []
        cn_set = called_function_names(h.ast_node)

        for imp in pr.imports:
            alias = imp.alias or imp.name
            if alias not in cn_set:
                continue
            root = imp.module.split(".")[0]
            if root in SKIP_MODULES:
                continue

            # 버그 24 수정: pr.project_root 전달 — zip 업로드 임시 폴더 구조에서
            # 외부 파일을 올바르게 찾기 위해 필요 (누락 시 WHSEC-005가 항상 INFO로 나옴)
            ext_pr = self._ast_engine.resolve_import(imp, pr.filepath, pr.project_root)
            # 순환 참조 방지: 이미 탐색한 파일이면 건너뜀
            if ext_pr is not None and ext_pr.filepath in _visited:
                continue
            if ext_pr is not None:
                _visited.add(ext_pr.filepath)

            if ext_pr is None:
                findings.append(Finding(
                    rule_id="WHSEC-005",
                    rule_name="외부 위임 소스 미확인",
                    severity=Severity.INFO,
                    message=f"'{imp.module}.{imp.name}' 소스를 찾을 수 없음. 수동 검토 필요.",
                    filepath=pr.filepath, handler_name=h.name,
                    lineno=h.lineno, cvss_score=0.0,
                    recommendation="위임 함수 소스를 직접 확인하세요.",
                ))
                continue

            if imp.name not in ext_pr.functions:
                continue
            ext_func = ext_pr.functions[imp.name]

            # == 비교 탐지
            for cmp in collect_comparisons(ext_func.ast_node):
                for op in cmp.ops:
                    if not isinstance(op, (ast.Eq, ast.NotEq)):
                        continue
                    ops = [cmp.left] + cmp.comparators
                    if any(isinstance(o, ast.Name) and
                           any(kw in o.id.lower() for kw in SIG_VAR_KEYWORDS)
                           for o in ops):
                        fix = FIX_SNIPPETS["WHSEC-005"].format(
                            module=imp.module, func=imp.name)
                        findings.append(Finding(
                            rule_id="WHSEC-005",
                            rule_name="외부 위임 타이밍 공격",
                            severity=Severity.MEDIUM,
                            message=f"'{imp.module}.{imp.name}()'에서 서명을 == 비교.",
                            filepath=pr.filepath, handler_name=h.name,
                            lineno=getattr(cmp, "lineno", 0),
                            cvss_score=6.5,
                            recommendation=f"{imp.module}.py에서 compare_digest 사용",
                            fix_snippet=fix,
                        ))

            # 취약 해시 탐지
            for child in ast.walk(ext_func.ast_node):
                if not isinstance(child, ast.Call):
                    continue
                cn = get_call_name(child)
                if cn == "hmac.new" and len(child.args) >= 3:
                    algo = self._extract_algo(child.args[2])
                    if algo in WEAK_ALGORITHMS:
                        # SHA1 vs MD5 분리: WHSEC-003과 동일한 기준 적용
                        # MD5 → AC:Low, C:High → 9.1 CRITICAL
                        # SHA1 → AC:High, C:Low → 6.5 MEDIUM
                        sev   = Severity.CRITICAL if algo == "md5" else Severity.MEDIUM
                        score = 9.1               if algo == "md5" else 6.5
                        findings.append(Finding(
                            rule_id="WHSEC-005",
                            rule_name="외부 위임 취약 해시",
                            severity=sev,
                            message=f"'{imp.module}.{imp.name}()'에서 {algo.upper()} 사용.",
                            filepath=pr.filepath, handler_name=h.name,
                            lineno=getattr(child, "lineno", 0),
                            cvss_score=score,
                            recommendation=f"{imp.module}.py에서 hashlib.{algo} → hashlib.sha256",
                            fix_snippet=FIX_SNIPPETS.get(f"WHSEC-003-{algo}", ""),
                        ))
        return findings

    # ── 공통 헬퍼 ──
    def _has_verify(self, calls):
        for name in calls:
            if name in VERIFY_CALL_PATTERNS:
                return True
            if any(kw in name.lower() for kw in VERIFY_NAME_KEYWORDS):
                return True
        return False