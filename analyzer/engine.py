"""
analyzer/engine.py

코어 엔진 — AST 파서 + 라우트 추출

ParseResult는 project_root 필드를 포함하며, __init__.py 유무를 기반으로 프로젝트 루트를 자동 감지한다.
resolve_import()는 같은 디렉터리 → 프로젝트 루트 절대 경로 → 패키지(__init__.py) 순으로 파일을 탐색한다.
include_router / register_blueprint 패턴이 감지되면 라우터 분리 구조 경고를 표시한다.
"""
import ast
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple


# 데이터 클래스
@dataclass
class WebhookHandler:
    name: str
    lineno: int
    end_lineno: int
    route_path: str
    http_method: str
    ast_node: ast.FunctionDef
    source_code: str = ""


@dataclass
class FunctionInfo:
    name: str
    lineno: int
    ast_node: ast.FunctionDef


@dataclass
class ImportInfo:
    module: str
    name: str
    alias: Optional[str]
    lineno: int


@dataclass
class HeaderParam:
    name: str           # 파이썬 변수명
    header_name: str    # HTTP 헤더명
    required: bool


@dataclass
class RouteEndpoint:
    method: str
    path: str
    function_name: str
    path_params: List[str]
    header_params: List[HeaderParam]
    is_webhook: bool
    lineno: int


@dataclass
class ParseResult:
    filepath: str
    tree: ast.Module
    handlers: List[WebhookHandler]
    functions: Dict[str, FunctionInfo]
    imports: List[ImportInfo]
    routes: List[RouteEndpoint]
    source_lines: List[str]
    project_root: str = ""          # 프로젝트 루트 경로
    has_router_split: bool = False  # include_router 패턴 감지 여부
    errors: List[str] = field(default_factory=list)


# 상수
WEBHOOK_PATH_KEYWORDS = ["webhook", "hook", "callback", "notify", "event"]

# 경로 키워드가 없더라도 서명 헤더 파라미터가 있으면 웹훅 핸들러로 판단.
# 사용자가 /api/v1/payment 같이 키워드 없는 경로를 써도 탐지 가능.
WEBHOOK_SIG_PARAMS = {
    "x_hub_signature_256",      # GitHub
    "x_hub_signature",          # GitHub 레거시
    "stripe_signature",          # Stripe
    "stripe_sig",
    "x_slack_signature",         # Slack
    "tosspayments_webhook_signature",   # 토스페이먼츠
    "toss_webhook_signature",
    "webhook_signature",         # PortOne V2 / Generic
    "x_signature",
    "x_webhook_signature",
    "x_secret",
}


# 유틸리티 함수 (SAST 규칙에서도 사용)
def get_call_name(call_node: ast.Call) -> str:
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def collect_calls(node: ast.AST) -> List[Tuple[str, int]]:
    return [(get_call_name(c), getattr(c, "lineno", 0))
            for c in ast.walk(node) if isinstance(c, ast.Call)]


def collect_comparisons(node: ast.AST) -> List[ast.Compare]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Compare)]


def called_function_names(node: ast.AST) -> Set[str]:
    # ast.Name(단순 호출)과 ast.Attribute(메서드 호출)을 모두 수집
    # self.verify(), utils.check_sig(), validator.verify_hmac() 등 다양한 호출 형태 탐지 가능
    names = set()
    for c in ast.walk(node):
        if not isinstance(c, ast.Call):
            continue
        if isinstance(c.func, ast.Name):
            names.add(c.func.id)
        elif isinstance(c.func, ast.Attribute):
            names.add(c.func.attr)
    return names


def var_to_header(var_name: str) -> str:
    """x_hub_signature_256 → X-Hub-Signature-256"""
    return "-".join(p.capitalize() for p in var_name.split("_"))


# 엔진
class WebhookASTEngine:

    def parse_file(self, filepath: str, project_root: str = "") -> ParseResult:
        """
        파일을 파싱하고 ParseResult 반환.
        project_root: zip 업로드 시 임시 폴더 루트 경로.
                      비워두면 __init__.py 유무로 자동 감지.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        return self.parse_source(source, filepath, project_root)

    def parse_source(self, source: str, filepath: str = "<string>",
                     project_root: str = "") -> ParseResult:
        source_lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as e:
            return ParseResult(filepath=filepath,
                               tree=ast.Module(body=[], type_ignores=[]),
                               handlers=[], functions={}, imports=[],
                               routes=[], source_lines=source_lines,
                               errors=[f"SyntaxError: {e}"])

        imports = self._extract_imports(tree)
        functions = self._extract_functions(tree)
        handlers = self._find_handlers(tree, source_lines)
        routes = self._extract_routes(tree)
        has_router_split = self._detect_router_split(tree)

        # 프로젝트 루트: 명시적으로 전달받으면 사용, 아니면 자동 감지
        resolved_root = project_root or self._find_project_root(filepath)

        return ParseResult(
            filepath=filepath,
            tree=tree,
            handlers=handlers,
            functions=functions,
            imports=imports,
            routes=routes,
            source_lines=source_lines,
            project_root=resolved_root,
            has_router_split=has_router_split,
        )

    # 프로젝트 루트 자동 감지
    def _find_project_root(self, filepath: str) -> str:
        """
        파일 경로에서 프로젝트 루트를 찾아 반환.

        판단 기준:
          현재 디렉터리에 __init__.py 가 없으면 그 디렉터리가 루트.
          있으면 상위로 올라가며 반복.

        예시:
          /tmp/proj/app/webhooks/handler.py
            app/webhooks/ → __init__.py 있음 → 상위로
            app/         → __init__.py 있음 → 상위로
            /tmp/proj/   → __init__.py 없음 → 여기가 루트 ✓
        """
        if filepath == "<string>":
            return ""
        current = os.path.dirname(os.path.abspath(filepath))
        while True:
            parent = os.path.dirname(current)
            if parent == current:
                # 파일시스템 최상위에 도달 — 시작 디렉터리를 루트로 사용
                return os.path.dirname(os.path.abspath(filepath))
            if not os.path.isfile(os.path.join(current, "__init__.py")):
                # __init__.py 없음 → 여기가 프로젝트 루트
                return current
            current = parent

    # include_router 패턴 감지
    def _detect_router_split(self, tree: ast.Module) -> bool:
        """
        app.include_router() 또는 blueprint.register_blueprint() 호출을 감지.
        True 반환 시: 핸들러가 여러 파일에 분산되어 있을 가능성.
        app.py가 이 값을 보고 "다른 파일도 함께 분석" 경고를 표시.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = get_call_name(node)
            if "include_router" in name or "register_blueprint" in name:
                return True
        return False

    # import 추출
    def _extract_imports(self, tree: ast.Module) -> List[ImportInfo]:
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    out.append(ImportInfo(node.module, a.name, a.asname, node.lineno))
            elif isinstance(node, ast.Import):
                for a in node.names:
                    out.append(ImportInfo(a.name, a.name, a.asname, node.lineno))
        return out

    # 함수 정의 수집
    def _extract_functions(self, tree: ast.Module) -> Dict[str, FunctionInfo]:
        return {node.name: FunctionInfo(node.name, node.lineno, node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

    # 웹훅 핸들러 식별
    def _find_handlers(self, tree: ast.Module, src: List[str]) -> List[WebhookHandler]:
        handlers = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                info = self._parse_decorator(dec)
                if info is None:
                    continue
                path, method = info

                # 감지 조건 1: 경로에 webhook/hook/callback 등 키워드 포함
                path_match = any(kw in path.lower() for kw in WEBHOOK_PATH_KEYWORDS)

                # 감지 조건 2: 함수 파라미터에 서명 헤더 파라미터 포함
                # 예) x_hub_signature_256, stripe_signature 등
                # 경로 이름이 /api/v1/payment 처럼 키워드 없어도 탐지 가능
                sig_match = any(
                    arg.arg.lower() in WEBHOOK_SIG_PARAMS
                    for arg in node.args.args
                )

                if not path_match and not sig_match:
                    continue

                end = node.end_lineno or node.lineno
                snippet = "\n".join(src[node.lineno - 1:end])
                handlers.append(WebhookHandler(
                    node.name, node.lineno, end, path, method, node, snippet))
                break
        return handlers

    # 라우트 추출 (DAST용)
    def _extract_routes(self, tree: ast.Module) -> List[RouteEndpoint]:
        routes = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                info = self._parse_decorator(dec)
                if info is None:
                    continue
                path, method = info
                path_params = re.findall(r"\{(\w+)\}", path)
                header_params = self._extract_header_params(node)
                # 경로 키워드 OR 서명 파라미터명 중 하나라도 해당하면 웹훅으로 판단
                # (_find_handlers()와 동일한 기준 적용)
                is_webhook = any(kw in path.lower() for kw in WEBHOOK_PATH_KEYWORDS) or \
                             any(arg.arg.lower() in WEBHOOK_SIG_PARAMS
                                 for arg in node.args.args)
                routes.append(RouteEndpoint(
                    method.upper(), path, node.name, path_params,
                    header_params, is_webhook, node.lineno))
                break
        return routes

    def _parse_decorator(self, dec: ast.expr) -> Optional[Tuple[str, str]]:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return None
        method = dec.func.attr
        if method not in ("post", "get", "put", "delete", "patch", "route"):
            return None
        path = ""
        if dec.args and isinstance(dec.args[0], ast.Constant):
            path = str(dec.args[0].value)
        if method == "route":
            method = "get"
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant):
                            method = str(elt.value).lower()
                            break
        return (path, method)

    def _extract_header_params(self, func_node) -> List[HeaderParam]:
        params = []
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return params
        args = func_node.args
        nd, na = len(args.defaults), len(args.args)
        for i, default in enumerate(args.defaults):
            idx = na - nd + i
            if idx < 0 or idx >= na:
                continue
            arg = args.args[idx]
            if isinstance(default, ast.Call):
                cn = ""
                if isinstance(default.func, ast.Name):
                    cn = default.func.id
                if cn == "Header":
                    req = True
                    if default.args and isinstance(default.args[0], ast.Constant):
                        if default.args[0].value is None:
                            req = False
                    params.append(HeaderParam(arg.arg, var_to_header(arg.arg), req))
        return params

    # 동적 import 감지 (importlib / __import__)
    def detect_dynamic_imports(self, tree: ast.Module) -> list:
        """
        importlib.import_module() 또는 __import__() 사용을 감지.

        AST 정적 분석은 런타임에 결정되는 동적 import를 추적할 수 없습니다.
        따라서 동적 import가 발견되면 즉시 INFO Finding을 생성해
        리포트에 "동적 임포트 감지됨 — DAST 동적 분석으로 검증 대체" 안내를 표시합니다.

        반환: 감지된 동적 import 위치 목록 [(함수명_또는_모듈명, 줄번호)]
        """
        DYNAMIC_IMPORT_PATTERNS = {
            "importlib.import_module",
            "importlib.import",
            "__import__",
            "import_module",
        }
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = get_call_name(node)
            if name in DYNAMIC_IMPORT_PATTERNS:
                found.append((name, getattr(node, "lineno", 0)))
        return found

    # 외부 파일 파싱
    def resolve_import(self, imp: ImportInfo, base_filepath: str,
                       project_root: str = "") -> Optional[ParseResult]:
        """
        import 경로를 실제 .py 파일로 해석.

        탐색 순서 (첫 번째 히트에서 반환):
          1) 같은 디렉터리에서 module.py
          2) 같은 디렉터리에서 module/__init__.py  (패키지)
          3) 프로젝트 루트에서 module/path.py      (절대 import)
          4) 프로젝트 루트에서 module/path/__init__.py

        추적 깊이: 이 함수는 깊이 1만 해석 (SAST가 재귀적으로 max_depth 관리).
        """
        if imp.module == "__future__":
            return None

        base_dir = os.path.dirname(os.path.abspath(base_filepath))
        module_rel = imp.module.replace(".", os.sep)

        # project_root: 인자로 받거나 ParseResult에서 가져오거나 자동 감지
        root = project_root or self._find_project_root(base_filepath)

        # 탐색할 루트 목록 (중복 제거)
        search_roots: List[str] = [base_dir]
        if root and os.path.isdir(root) and root != base_dir:
            search_roots.append(root)

        for search_root in search_roots:
            # 1) module.py
            candidate = os.path.join(search_root, module_rel + ".py")
            if os.path.isfile(candidate):
                return self.parse_file(candidate, root)

            # 2) module/__init__.py  (패키지)
            candidate_pkg = os.path.join(search_root, module_rel, "__init__.py")
            if os.path.isfile(candidate_pkg):
                return self.parse_file(candidate_pkg, root)

        return None