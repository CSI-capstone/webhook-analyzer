"""
analyzer/sast.py

정적 분석(SAST) — 5개 규칙 통합 + 수정 코드 스니펫

규칙 목록:
  WHSEC-001  서명 검증 누락
  WHSEC-002  타이밍 공격 (== 비교)
  WHSEC-003  취약한 해시 알고리즘
  WHSEC-004  타임스탬프 검증 누락
  WHSEC-005  외부 파일 위임 결함

각 규칙은 Finding 객체와 함께 자동 수정 코드 스니펫(fix_snippet)을 생성합니다.
SAST는 소스코드 기반으로 동작하며 Tier에 따른 동작 차이는 없습니다.
"""
import ast
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set

from analyzer.ast_checks import ASTChecks, call_name, canonical, signature_compare

from analyzer.engine import (
    WebhookHandler, FunctionInfo, ParseResult, WebhookASTEngine,
    collect_calls, collect_comparisons, get_call_name, called_function_names,
)


# 데이터 구조
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
    fix_snippet: str = ""
    code_snippet: str = ""
    origin_filepath: str = ""
    related_rule_ids: List[str] = field(default_factory=list)


# 상수
VERIFY_CALL_PATTERNS = {"hmac.new", "hmac.compare_digest", "hmac.digest"}
VERIFY_NAME_KEYWORDS = {"verify", "validate", "check_sig", "check_signature"}
SIG_VAR_KEYWORDS = {"sig", "signature", "hash", "computed", "expected",
                     "digest", "hmac", "x_hub_signature", "x_signature",
                     "stripe_signature"}
WEAK_ALGORITHMS = {"sha1", "md5"}
TIMESTAMP_KEYWORDS = {"timestamp", "time", "ts", "nonce", "expires"}

# 헤더 문자열 검색은 명확한 타임스탬프 헤더명으로만 제한한다.
# "time", "ts" 같은 짧은 단어는 부분 매칭 시 "X-Request-Timeout" 같은
# 무관한 헤더에도 반응해 오탐이 발생할 수 있기 때문이다.
TIMESTAMP_HEADER_STRINGS = {
    "x-timestamp",
    "x-slack-request-timestamp",
    "stripe-timestamp",
    "toss-timestamp",
    "x-request-timestamp",
    "webhook-timestamp",
    "tosspayments-webhook-transmission-time",
}
TIME_CALL_PATTERNS = {"time.time", "datetime.now", "datetime.utcnow"}
SKIP_MODULES = {"fastapi", "flask", "django", "starlette", "pydantic",
                "hashlib", "hmac", "json", "os", "sys", "time", "datetime",
                "typing", "logging", "stripe", "requests", "httpx", "aiohttp"}


# 수정 코드 스니펫 템플릿
FIX_SNIPPETS = {
    "WHSEC-001": '''\
# ── 참고 예제: 사용자 정의 HMAC 서명 검증 ──
# 실제 GitHub/Stripe/Slack/Toss/PortOne의 헤더·서명 입력·SDK 명세에 맞춰 적용하세요.
import hmac, hashlib, os
from fastapi import Request, HTTPException, Header

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()

@app.post("{route}")
async def {func}(
    request: Request,
    {sig_param}: str = Header(None),
):
    payload = await request.body()
    if {sig_param} is None:
        raise HTTPException(401, "Missing signature")
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET, payload, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest({sig_param}, expected):
        raise HTTPException(401, "Invalid signature")
    data = await request.json()
    # ... 안전하게 처리 ...
    return {{"status": "ok"}}
''',

    "WHSEC-002": '''\
# ── 수정: == 대신 hmac.compare_digest 사용 ──
# 변경 전 (취약):
#   if {left} == {right}:
# 변경 후 (안전):
if hmac.compare_digest({left}, {right}):
    # 서명 일치 — 처리 진행
    pass
''',

    "WHSEC-003-sha1": '''\
# ── 수정: SHA1 → SHA256 교체 ──
# 변경 전 (취약):
#   computed = hmac.new({secret}, {payload}, hashlib.sha1).hexdigest()
# 변경 후 (안전):
computed = "sha256=" + hmac.new(
    {secret}, {payload}, hashlib.sha256
).hexdigest()
''',

    "WHSEC-003-md5": '''\
# ── 수정: MD5 → SHA256 교체 ──
# 변경 전 (취약):
#   computed = hmac.new({secret}, {payload}, hashlib.md5).hexdigest()
# 변경 후 (안전):
computed = "sha256=" + hmac.new(
    {secret}, {payload}, hashlib.sha256
).hexdigest()
''',

    "WHSEC-004-header": '''\
# ── 예제: 타임스탬프 검증 추가 ──
# 시간값도 제공자 명세에 따라 서명으로 보호되어야 합니다.
# GitHub 등 시간 서명이 없는 프로토콜에는 이 예제를 그대로 적용하지 마세요.

# [1단계] 파일 상단 (import 아래)에 추가
import time

TIMESTAMP_TOLERANCE = 300  # 5분

def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    return abs(time.time() - ts) <= TIMESTAMP_TOLERANCE

# [2단계] 핸들러 내부, 서명 검증 직전에 추가
{ts_var} = request.headers.get("{ts_header}")
if not {ts_var} or not verify_timestamp({ts_var}):
    raise HTTPException(401, "Timestamp expired or invalid")
''',

    "WHSEC-004-param": '''\
# ── 예제: 타임스탬프 검증 추가 ──
# 시간값도 제공자 명세에 따라 서명으로 보호되어야 합니다.
# GitHub 등 시간 서명이 없는 프로토콜에는 이 예제를 그대로 적용하지 마세요.

# [1단계] 파일 상단 (import 아래)에 추가
import time

TIMESTAMP_TOLERANCE = 300  # 5분

def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    return abs(time.time() - ts) <= TIMESTAMP_TOLERANCE

# [2단계] 핸들러 내부, 서명 검증 직전에 추가
# ({ts_var} 는 이미 파라미터로 받고 있으므로 그대로 사용)
if not {ts_var} or not verify_timestamp({ts_var}):
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


# SAST 엔진
class SASTEngine:
    """정적 분석 5개 규칙 통합 실행"""

    def __init__(self):
        self._ast_engine = WebhookASTEngine()
        self._checks = ASTChecks(self._ast_engine)

    def analyze_file(self, filepath: str) -> List[Finding]:
        pr = self._ast_engine.parse_file(filepath)
        return self.analyze(pr)

    def analyze(self, pr: ParseResult) -> List[Finding]:
        findings = []
        self._checks.cache.clear()

        # importlib 등 동적 import가 감지된 경우 INFO Finding을 생성한다.
        # 런타임에 결정되는 import 경로는 AST 정적 분석으로 추적할 수 없으므로
        # DAST 동적 분석 결과를 함께 참고하도록 안내한다.
        dynamic_imports = self._ast_engine.detect_dynamic_imports(pr.tree)
        for name, lineno in dynamic_imports:
            findings.append(Finding(
                rule_id="WHSEC-DYN",
                rule_name="동적 임포트 감지",
                severity=Severity.INFO,
                message=f"동적 임포트({name}) 감지됨 — 정적 추적 불가. 해당 경로는 수동 검토와 DAST 추가 확인이 필요합니다.",
                filepath=pr.filepath,
                handler_name="(파일 전체)",
                lineno=lineno,
                cvss_score=0.0,
                recommendation="importlib 사용 시 정적 분석 범위를 벗어납니다. 미추적 경로를 안전하다고 해석하지 마세요.",
            ))

        # 핸들러별 규칙 적용
        for handler in pr.handlers:
            findings.extend(self._rule_01(handler, pr))
            findings.extend(self._rule_02(handler, pr))
            findings.extend(self._rule_03(handler, pr))
            findings.extend(self._rule_04(handler, pr))
            findings.extend(self._rule_05(handler, pr))
        return findings

    # WHSEC-001: 서명 검증 누락
    def _rule_01(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        if self._checks.validates(h.ast_node, pr):
            return []
        if self._checks.unknown_verifier(h.ast_node, pr):
            return [Finding(
                rule_id="WHSEC-001", rule_name="서명 검증 확인 불가",
                severity=Severity.INFO,
                message=f"핸들러 '{h.name}': 검증 호출의 구현을 추적하지 못했습니다. 안전 판정 불가.",
                filepath=pr.filepath, handler_name=h.name, lineno=h.lineno,
                recommendation="검증 함수 소스 또는 사용 SDK의 실패 처리 경로를 확인하세요.",
            )]

        # 핸들러 파라미터에서 실제 서명 헤더 변수명 추출
        sig_param = "x_hub_signature_256"
        if isinstance(h.ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in h.ast_node.args.args:
                if any(kw in arg.arg.lower() for kw in {"sig", "signature", "hash"}):
                    sig_param = arg.arg
                    break

        fix = FIX_SNIPPETS["WHSEC-001"].format(
            route=h.route_path, func=h.name, sig_param=sig_param,
        )
        return [Finding(
            rule_id="WHSEC-001",
            rule_name="서명 검증 누락",
            severity=Severity.CRITICAL,
            message=f"핸들러 '{h.name}' ({h.route_path})에서 서명 비교 결과로 처리를 제한하는 지원 패턴을 찾지 못했습니다.",
            filepath=pr.filepath, handler_name=h.name,
            lineno=h.lineno, end_lineno=h.end_lineno,
            cvss_score=9.8,
            recommendation="HMAC-SHA256 서명 검증을 추가하세요.",
            fix_snippet=fix,
            code_snippet=h.source_code[:300],
        )]

    # WHSEC-002: 타이밍 공격 (== 비교)
    def _rule_02(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        findings = []
        for context, node, external in self._checks.reachable(h.ast_node, pr):
            if not external:
                findings.extend(self._check_eq(node, h, context, "" if node is h.ast_node else node.name))
        return findings

    def _check_eq(self, node, h, pr, delegated):
        findings = []
        for cmp in collect_comparisons(node):
            if not signature_compare(cmp):
                continue
            left, right = ast.unparse(cmp.left), ast.unparse(cmp.comparators[0])
            negated = isinstance(cmp.ops[0], ast.NotEq)
            expression = f"{'not ' if negated else ''}hmac.compare_digest({left}, {right})"
            fix = ("# 비교 조건만 바꾸고 기존 성공/거부 분기는 유지하세요.\n"
                   "import hmac\n" + f"if {expression}:\n    # 기존 분기 내용\n    pass\n")
            findings.append(Finding(
                rule_id="WHSEC-002", rule_name="서명 일반 비교 사용",
                severity=Severity.HIGH,
                message=f"핸들러 '{h.name}' (함수: {node.name})에서 서명을 일반 비교합니다. 타이밍 노출 가능성 검토 필요.",
                filepath=pr.filepath, handler_name=h.name, lineno=cmp.lineno,
                cvss_score=7.4, fix_snippet=fix,
                recommendation="상수 시간 비교를 사용하고 != 조건의 부정 의미를 유지하세요.",
            ))
        return findings

    # WHSEC-003: 취약한 해시 알고리즘
    def _rule_03(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        findings = []
        for context, node, external in self._checks.reachable(h.ast_node, pr):
            if not external:
                findings.extend(self._check_hash(node, h, context, "" if node is h.ast_node else node.name))
        return findings

    def _check_hash(self, node, h, pr, delegated):
        findings = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or call_name(child, pr) not in {"hmac.new", "hmac.digest"}:
                continue
            digest = next((kw.value for kw in child.keywords if kw.arg in {"digestmod", "digest"}), None)
            if digest is None and len(child.args) >= 3:
                digest = child.args[2]
            algo = self._extract_algo(digest, pr)
            if algo not in WEAK_ALGORITHMS:
                continue
            secret = ast.unparse(child.args[0]) if child.args else "secret"
            payload = ast.unparse(child.args[1]) if len(child.args) > 1 else "payload"
            # 통신 상대와 함께 변경할 예제이다. 접두사/인코딩을 일방적으로 추가하지 않는다.
            fix = ("# 제공자 명세와 호환되는지 확인하고 송신 측과 함께 변경하세요.\n"
                   "import hmac, hashlib\n"
                   f"computed = hmac.new({secret}, {payload}, hashlib.sha256).hexdigest()\n"
                   "# 실제 헤더 접두사와 hex/Base64 인코딩은 해당 플랫폼 명세를 따르세요.\n")
            findings.append(Finding(
                rule_id="WHSEC-003", rule_name="레거시 HMAC 알고리즘",
                severity=Severity.MEDIUM,
                message=f"핸들러 '{h.name}' (함수: {node.name}): HMAC-{algo.upper()} 사용. 신규 구현은 SHA-256 권장; 서명 위조 성공의 증거는 아닙니다.",
                filepath=pr.filepath, handler_name=h.name, lineno=child.lineno,
                cvss_score=6.5, fix_snippet=fix,
                recommendation="허용 알고리즘 정책과 제공자 명세를 확인하세요. 해시 충돌과 HMAC 위조는 구분해야 합니다.",
            ))
        return findings

    def _extract_algo(self, node, pr=None):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.lower().replace('-', '')
        if isinstance(node, ast.Name):
            name = canonical(node.id, pr) if pr else node.id
        elif isinstance(node, ast.Attribute):
            name = canonical(ast.unparse(node), pr) if pr else ast.unparse(node)
        else:
            return ""
        return name.rsplit('.', 1)[-1] if name.rsplit('.', 1)[-1] in WEAK_ALGORITHMS else ""

    # WHSEC-004: 타임스탬프 검증 누락
    def _rule_04(self, h: WebhookHandler, pr: ParseResult) -> List[Finding]:
        if not self._handler_has_sig(h, pr):
            return []
        if not self._has_ts_param(h.ast_node):
            return []
        if self._has_ts_check(h, pr):
            return []

        ts_header, ts_var, is_param = self._get_ts_header_name(h.ast_node)
        if is_param:
            fix = FIX_SNIPPETS["WHSEC-004-param"].format(ts_var=ts_var)
        else:
            fix = FIX_SNIPPETS["WHSEC-004-header"].format(
                ts_header=ts_header, ts_var=ts_var,
            )
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
            fix_snippet=fix,
        )]

    def _get_ts_header_name(self, node):
        """타임스탬프 헤더명과 변수명, 파라미터 여부를 반환한다.

        반환: (ts_header, ts_var, is_param)
          - is_param=True  : FastAPI Header 파라미터로 받는 케이스
                             → request.headers.get() 줄 불필요
          - is_param=False : 본문에서 request.headers.get()으로 직접 읽는 케이스
                             → request.headers.get() 줄 필요
        """
        # 1순위: 문자열 상수에서 명확한 타임스탬프 헤더명 검색
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value.lower() in TIMESTAMP_HEADER_STRINGS:
                    ts_header = child.value
                    ts_var = ts_header.lower().replace("-", "_")
                    return ts_header, ts_var, False
        # 2순위: FastAPI Header 파라미터에서 탐색 (서명 관련 키워드 제외)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args:
                name = arg.arg.lower()
                if any(kw in name for kw in SIG_VAR_KEYWORDS):
                    continue
                if any(kw in name for kw in TIMESTAMP_KEYWORDS):
                    ts_var = arg.arg
                    ts_header = "-".join(p.capitalize() for p in arg.arg.split("_"))
                    return ts_header, ts_var, True
        return "X-Timestamp", "x_timestamp", False

    def _handler_has_sig(self, h, pr):
        return any(call_name(call, context).startswith("hmac.")
                   for context, node, _ in self._checks.reachable(h.ast_node, pr)
                   for call in ast.walk(node) if isinstance(call, ast.Call)) or self._checks.validates(h.ast_node, pr)

    def _has_ts_param(self, node):
        if any(isinstance(n, ast.Name) and n.id in {"stripe_signature", "stripe_sig"} for n in ast.walk(node)):
            return True
        # 함수 파라미터 이름에서 검색
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args:
                if any(kw in arg.arg.lower() for kw in TIMESTAMP_KEYWORDS):
                    return True
        # 문자열 상수 검색은 명확한 헤더명으로만 제한한다.
        # 부분 매칭을 허용하면 "X-Request-Timeout" 같은 무관한 헤더도 걸릴 수 있다.
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value.lower() in TIMESTAMP_HEADER_STRINGS:
                    return True
        return False

    def _has_ts_check(self, h, pr):
        return self._checks.validates(h.ast_node, pr, mode="timestamp")

    # WHSEC-005: 외부 파일 위임 결함
    def _rule_05(self, h: WebhookHandler, pr: ParseResult, _visited=None) -> List[Finding]:
        findings = []
        for context, node, external in self._checks.reachable(h.ast_node, pr):
            if not external:
                continue
            for finding in self._check_eq(node, h, context, node.name) + self._check_hash(node, h, context, node.name):
                underlying = finding.rule_id
                finding.rule_id = "WHSEC-005"
                finding.rule_name = "외부 검증 함수 내부 결함"
                finding.origin_filepath = pr.filepath
                finding.related_rule_ids = [underlying]
                findings.append(finding)
        for call in (n for n in ast.walk(h.ast_node) if isinstance(n, ast.Call)):
            name = get_call_name(call)
            for imp in pr.imports:
                binding = imp.alias or imp.name.split('.')[0]
                if name.split('.')[0] != binding or (imp.module.split('.')[0] in SKIP_MODULES or imp.module.split('.')[0] in sys.stdlib_module_names):
                    continue
                if not self._checks.resolve(name, pr):
                    findings.append(Finding(
                        rule_id="WHSEC-005", rule_name="외부 위임 소스 미확인",
                        severity=Severity.INFO,
                        message=f"'{name}' 구현을 추적하지 못했습니다. 수동 검토 필요.",
                        filepath=pr.filepath, handler_name=h.name, lineno=call.lineno,
                        recommendation="ZIP에 위임 함수 소스를 포함하고 import 경로를 확인하세요.",
                    ))
        return findings
