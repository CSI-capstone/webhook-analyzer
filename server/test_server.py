"""
server/test_server.py — DAST 테스트용 로컬 웹훅 서버

[역할]
  stdlib의 http.server 만으로 구현한 경량 테스트 서버.
  취약/안전 웹훅 엔드포인트를 동시에 제공하여
  DAST 엔진의 탐지 정확도를 검증한다.

[취약 엔드포인트 — vulnerable_webhook.py 대응]
  POST /webhook/no-verify         [V1] 서명 검증 자체 없음
  POST /webhook/timing-attack     [V2] == 비교로 타이밍 공격 가능
  POST /webhook/weak-hash-sha1    [V3a] SHA1 사용
  POST /webhook/weak-hash-md5     [V3b] MD5 사용
  POST /webhook/no-timestamp      [V4] 타임스탬프 검증 없음

[안전 엔드포인트 — secure_webhook.py 대응]
  POST /webhook/secure            sha256 + compare_digest + 타임스탬프 검증

[상태 교차 검증용 엔드포인트 (Tier 1)]
  POST /orders                    주문 생성 (request body의 order_id, status 저장)
  GET  /orders/{id}               주문 조회 (order_id로 상태 반환)

[내부 구현]
  - 인메모리 딕셔너리(_order_db)를 주문 DB로 사용
  - threading.Lock 으로 동시 접근 제어
  - 서명 생성 헬퍼: _sig256(), _sig1(), _sigmd5()
  - reset_db(): 테스트 간 DB 초기화
  - start_server(port): 별도 스레드에서 서버 기동 (daemon=True)

[서버 설정]
  SECRET              : b"supersecretkey"
  TIMESTAMP_TOLERANCE : 300초 (5분)
"""

# TODO: 상수 정의 (SECRET, TIMESTAMP_TOLERANCE)
# TODO: 인메모리 주문 DB + Lock 정의
# TODO: 서명 생성 헬퍼 함수 (_sig256, _sig1, _sigmd5)
# TODO: BaseHTTPRequestHandler 상속 Handler 클래스 구현
#   - do_POST(): 경로별 핸들러 메서드 디스패치
#   - do_GET(): /orders/{id} 조회 처리
#   - 각 취약/안전 엔드포인트 메서드 (_v1, _v2, _v3a, _v3b, _v4, _safe)
#   - _create_order(): POST /orders 주문 생성
#   - _get_order(): GET /orders/{id} 주문 조회
#   - _body(): Content-Length 기반 요청 본문 읽기
#   - _json(): JSON 응답 전송 헬퍼
# TODO: reset_db() 함수 구현 (테스트 초기화용)
# TODO: start_server(port) 함수 구현 (daemon thread로 기동)
