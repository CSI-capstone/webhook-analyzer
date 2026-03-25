"""
app.py — FastAPI 애플리케이션 진입점

[역할]
  웹 UI와 REST API를 제공하는 FastAPI 앱.
  업로드된 파일을 받아 분석 파이프라인을 실행하고 결과를 JSON으로 반환한다.

[엔드포인트]
  GET  /          → frontend/index.html 반환
  GET  /health    → 서버 상태 확인 (버전, 플랫폼 감지 여부)
  POST /analyze   → 분석 실행 메인 엔드포인트

[POST /analyze 처리 흐름]
  1) 업로드 파일 수신 (UploadFile: .py 또는 .zip)
  2) backend/upload.py 를 통해 임시 폴더에 저장 및 .py 파일 목록 추출
  3) analyzer/engine.py 로 AST 파싱
  4) analyzer/platform.py 로 플랫폼 자동 감지
  5) analyzer/sast.py 로 정적 분석 실행
  6) webhook_url 이 입력된 경우 analyzer/dast.py 로 동적 분석 실행
  7) analyzer/report.py 로 통합 리포트 생성
  8) analyzer/serializer.py 로 JSON 직렬화 후 반환
  9) 임시 폴더 cleanup

[Form 파라미터]
  code          : 업로드 파일 (.py / .zip, 필수)
  webhook_url   : DAST 대상 서버 URL (선택, 비우면 SAST만 실행)
  state_create  : Tier 1 상태 생성 경로 (기본: /orders)
  state_query   : Tier 1 상태 조회 경로 템플릿 (기본: /orders/{id})
  secret        : HMAC 시크릿 키 (기본: supersecretkey)
  sast_only     : True면 DAST 건너뜀
"""

# TODO: FastAPI 인스턴스 생성
# TODO: GET / 라우트 구현 (frontend/index.html 반환)
# TODO: GET /health 라우트 구현
# TODO: POST /analyze 라우트 구현
#   - 파일 업로드 처리
#   - 분석 파이프라인 순서대로 호출
#   - include_router 감지 시 경고 메시지 포함
#   - DAST 실행 여부 조건 처리
#   - 에러 핸들링 (UploadError, 파싱 실패 등)
#   - 분석 소요 시간 측정 및 응답에 포함
