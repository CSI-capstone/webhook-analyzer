"""기존 SAST 5개 규칙의 보조 함수. 코드를 실행하지 않는 제한된 AST 추적이다."""
import ast
from dataclasses import replace
from analyzer.engine import get_call_name, ImportInfo, WebhookASTEngine

VERIFY_WORDS = ("verify", "validate", "check_sig", "signature")
SDK_VERIFIERS = {
    "stripe.Webhook.construct_event", "stripe.webhook.WebhookSignature.verify_header",
    "portone_server_sdk.webhook.verify", "standardwebhooks.webhooks.Webhook.verify",
}
TIME_CALLS = {"time.time", "datetime.now", "datetime.utcnow", "datetime.datetime.now",
              "datetime.datetime.utcnow"}


def aliases(pr):
    return {(i.alias or (i.name if i.module != i.name else i.name.split('.')[0])):
            (f"{i.module}.{i.name}" if i.module and i.module != i.name else i.name)
            for i in pr.imports}


def canonical(name, pr):
    first, *rest = name.split('.')
    return '.'.join([aliases(pr).get(first, first)] + rest)


def call_name(node, pr):
    return canonical(get_call_name(node), pr)


def is_sig_name(name):
    name = name.lower()
    return any(word in name for word in ("signature", "sig", "digest", "hmac")) or name in {"computed", "expected"}


def signature_compare(node):
    if not isinstance(node, ast.Compare) or not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
        return False
    values = [node.left] + node.comparators
    # None/빈 헤더 존재 확인을 타이밍 공격으로 취급하지 않는다.
    if any(isinstance(v, ast.Constant) and (v.value is None or v.value == '') for v in values):
        return False
    return any(is_sig_name(n.id) for value in values for n in ast.walk(value) if isinstance(n, ast.Name))


class ASTChecks:
    MAX_LOCAL_DEPTH = 4

    def __init__(self, engine=None):
        self.engine = engine or WebhookASTEngine()
        self.cache = {}

    def resolve(self, name, pr):
        if name in pr.functions:
            return pr, pr.functions[name].ast_node
        first, *rest = name.split('.')
        for imp in pr.imports:
            binding = imp.alias or (imp.name.split('.')[0] if imp.module == imp.name else imp.name)
            if first != binding:
                continue
            target = imp
            function_name = imp.name
            if rest:
                function_name = rest[-1]
                module = imp.name if not imp.module else imp.module
                if imp.module and imp.module != imp.name:
                    module = f"{imp.module}.{imp.name}"
                target = replace(imp, module=module)
            key = (pr.filepath, target.module, target.level)
            if key not in self.cache:
                try:
                    self.cache[key] = self.engine.resolve_import(target, pr.filepath, pr.project_root)
                except (OSError, UnicodeError, ValueError):
                    self.cache[key] = None
            other = self.cache[key]
            if other and not other.errors and function_name in other.functions:
                return other, other.functions[function_name].ast_node
        return None

    def reachable(self, node, pr):
        """동일 파일은 최대 4단계, 외부 파일은 원래와 같이 1단계까지 추적한다."""
        seen = set()
        def visit(current, context, depth, external):
            key = (context.filepath, current.name)
            if key in seen:
                return
            seen.add(key)
            yield context, current, external
            if depth >= self.MAX_LOCAL_DEPTH:
                return
            for call in (n for n in ast.walk(current) if isinstance(n, ast.Call)):
                resolved = self.resolve(get_call_name(call), context)
                if not resolved:
                    continue
                next_pr, function = resolved
                next_external = next_pr.filepath != pr.filepath
                if external and next_external and next_pr.filepath != context.filepath:
                    continue
                yield from visit(function, next_pr, depth + 1, external or next_external)
        yield from visit(node, pr, 0, False)

    @staticmethod
    def assignments(node):
        values = {}
        for child in ast.walk(node):
            if isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    if isinstance(target, ast.Name) and child.value is not None:
                        values[target.id] = child.value
        return values

    def predicate(self, expr, node, pr, mode, seen=frozenset(), depth=0):
        if expr is None or depth > self.MAX_LOCAL_DEPTH:
            return False
        if isinstance(expr, ast.Name):
            key = (pr.filepath, node.name, expr.id)
            if key in seen:
                return False
            value = self.assignments(node).get(expr.id)
            return value is not None and self.predicate(value, node, pr, mode, seen | {key}, depth + 1)
        if mode == 'signature':
            if signature_compare(expr):
                return True
            if isinstance(expr, ast.Call) and call_name(expr, pr) == 'hmac.compare_digest':
                return True
        elif isinstance(expr, ast.Compare):
            # time.time() 로그 호출은 인정하지 않는다. 시간과 수신 시간의 실제 비교가 필요하다.
            expanded = list(ast.walk(expr))
            for n in list(expanded):
                if isinstance(n, ast.Name):
                    value = self.assignments(node).get(n.id)
                    if value is not None:
                        expanded.extend(ast.walk(value))
            has_clock = any(isinstance(n, ast.Call) and call_name(n, pr) in TIME_CALLS for n in expanded)
            has_timestamp = any(isinstance(n, ast.Name) and
                                (n.id.lower() in {'ts', 'timestamp', 'timestamp_str'} or
                                 any(w in n.id.lower() for w in ('timestamp', 'expires', 'event_time')))
                                for n in expanded)
            if has_clock and has_timestamp:
                return True
        if isinstance(expr, ast.Call):
            name = get_call_name(expr)
            key = (pr.filepath, name, mode)
            if key in seen:
                return False
            resolved = self.resolve(name, pr)
            if resolved:
                other, function = resolved
                return self.validates(function, other, mode, helper=True,
                                      seen=seen | {key}, depth=depth + 1)
        if isinstance(expr, (ast.UnaryOp, ast.BoolOp)):
            children = [expr.operand] if isinstance(expr, ast.UnaryOp) else expr.values
            return any(self.predicate(c, node, pr, mode, seen, depth + 1) for c in children)
        return False

    def failure_values(self, expr, node, pr, mode, depth=0):
        """검증 실패 시 조건이 가질 수 있는 값. 모르는 식은 두 값 모두로 본다."""
        if depth > self.MAX_LOCAL_DEPTH:
            return {False, True}
        if isinstance(expr, ast.Constant) and isinstance(expr.value, bool):
            return {expr.value}
        if isinstance(expr, ast.Name):
            value = self.assignments(node).get(expr.id)
            if value is not None:
                return self.failure_values(value, node, pr, mode, depth + 1)
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            return {not value for value in self.failure_values(expr.operand, node, pr, mode, depth + 1)}
        if isinstance(expr, ast.BoolOp):
            values = {True} if isinstance(expr.op, ast.And) else {False}
            for child in expr.values:
                candidates = self.failure_values(child, node, pr, mode, depth + 1)
                values = {(left and right) if isinstance(expr.op, ast.And) else (left or right)
                          for left in values for right in candidates}
            return values
        if self.predicate(expr, node, pr, mode):
            if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
                if mode == 'signature':
                    return {isinstance(expr.ops[0], ast.NotEq)}
                # 지원하는 시간 패턴: abs(now - ts) <= tolerance / > tolerance.
                return {isinstance(expr.ops[0], (ast.Gt, ast.GtE))}
            return {False}
        return {False, True}

    @staticmethod
    def rejects(statements, helper=False):
        for statement in statements:
            if isinstance(statement, ast.Raise):
                return True
            if isinstance(statement, ast.Return):
                value = statement.value
                if helper and isinstance(value, ast.Constant) and value.value is False:
                    return True
                if isinstance(value, ast.Call):
                    for kw in value.keywords:
                        if kw.arg == 'status_code' and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int) and 400 <= kw.value.value < 500:
                            return True
                    if any(isinstance(arg, ast.Constant) and isinstance(arg.value, int) and 400 <= arg.value < 500 for arg in value.args):
                        return True
                if isinstance(value, ast.Tuple) and len(value.elts) > 1:
                    code = value.elts[1]
                    if isinstance(code, ast.Constant) and isinstance(code.value, int) and 400 <= code.value < 500:
                        return True
        return False

    def validates(self, node, pr, mode='signature', helper=False, seen=frozenset(), depth=0):
        if depth > self.MAX_LOCAL_DEPTH:
            return False
        # 인식하는 SDK의 예외 기반 검증 호출. 임의 verify 이름은 여기에 포함하지 않는다.
        if mode == 'signature':
            for statement in node.body:
                value = statement.value if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)) else None
                if isinstance(value, ast.Call) and call_name(value, pr) in SDK_VERIFIERS:
                    return True
        for index, statement in enumerate(node.body):
            if (helper and isinstance(statement, ast.Return) and self.predicate(statement.value, node, pr, mode, seen, depth)
                    and self.failure_values(statement.value, node, pr, mode) == {False}):
                return True
            if not isinstance(statement, ast.If) or not self.predicate(statement.test, node, pr, mode, seen, depth):
                continue
            # 부정 검사에서 실제 거부하거나, 긍정 분기 반환 뒤 실패 경로가 거부되어야 한다.
            failure = self.failure_values(statement.test, node, pr, mode)
            if failure == {True} and self.rejects(statement.body, helper):
                return True
            if failure == {False} and self.rejects(statement.orelse, helper):
                return True
            has_return = any(isinstance(n, ast.Return) for n in ast.walk(statement))
            if has_return and failure == {False} and self.rejects(node.body[index + 1:], helper):
                return True
        return False

    def unknown_verifier(self, node, pr):
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            name = get_call_name(call)
            if any(word in name.lower() for word in VERIFY_WORDS) and not self.resolve(name, pr):
                if call_name(call, pr) not in SDK_VERIFIERS and call_name(call, pr) != 'hmac.compare_digest':
                    return True
        return False
