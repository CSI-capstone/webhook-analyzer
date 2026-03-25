"""
analyzer/engine.py — 코어 AST 파서 및 라우트 추출 엔진

[역할]
  Python 소스 파일을 AST(추상 구문 트리)로 파싱하여
  웹훅 핸들러 함수와 라우트 정보를 추출한다.
  SAST / DAST 양쪽 모두 이 엔진의 결과를 기반으로 동작한다.

[주요 데이터 클래스]
  WebhookHandler  : 웹훅 핸들러 함수 정보 (이름, 줄 번호, 라우트 경로, HTTP 메서드, AST 노드)
  FunctionInfo    : 파일 내 모든 함수 정보 (이름, 줄 번호, AST 노드)
  ImportInfo      : import 구문 정보 (모듈명, 심볼명, 별칭, 줄 번호)
  HeaderParam     : 핸들러가 받는 HTTP 헤더 파라미터 (변수명, 헤더명, 필수 여부)
  RouteEndpoint   : 라우트 엔드포인트 정보 (메서드, 경로, 함수명, 경로 파라미터, 헤더 파라미터)
  ParseResult     : 파일 하나의 파싱 결과 전체를 담는 컨테이너

[WebhookASTEngine 주요 메서드]
  parse_file(filepath, project_root)
    → ParseResult 반환
    → AST 파싱 → 함수/import/라우트 수집 → include_router 패턴 감지

  resolve_import(import_info, base_dir, project_root)
    → 외부 파일 import를 실제 파일 경로로 변환
    → 탐색 순서: ① 동일 디렉터리 ② 프로젝트 루트 기준 절대 경로 ③ 패키지 __init__.py

[유틸리티 함수 (module-level)]
  collect_calls(node)       → AST 노드에서 모든 함수 호출 목록 수집
  collect_comparisons(node) → AST 노드에서 모든 비교 연산 수집
  get_call_name(call_node)  → Call 노드에서 호출 이름 문자열 추출
  called_function_names(node) → 호출된 함수 이름 집합 반환

[include_router 감지]
  FastAPI의 include_router / Flask의 register_blueprint 패턴을 탐지하여
  ParseResult.has_router_split = True 로 표시 → 프론트엔드에 경고 표시
"""

# TODO: 데이터 클래스 정의 (WebhookHandler, FunctionInfo, ImportInfo, HeaderParam, RouteEndpoint, ParseResult)
# TODO: 유틸리티 함수 구현 (collect_calls, collect_comparisons, get_call_name, called_function_names)
# TODO: WebhookASTEngine 클래스 구현
#   - parse_file(): AST 파싱 + 전체 수집 파이프라인
#   - _collect_functions(): 함수 정의 수집
#   - _collect_imports(): import 구문 수집
#   - _collect_routes(): @app.route / @router.post 등 데코레이터 파싱
#   - _collect_header_params(): 핸들러 파라미터에서 Header(...) 추출
#   - _detect_router_split(): include_router / register_blueprint 감지
#   - resolve_import(): import 경로 → 실제 파일 경로 변환
#   - _find_project_root(): __init__.py 없는 첫 상위 디렉터리를 루트로 판단
