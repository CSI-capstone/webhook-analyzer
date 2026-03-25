"""
tests/test_integration.py — 전체 파이프라인 End-to-End 통합 테스트

[역할]
  SAST → Probe → DAST → Report 전체 흐름을 자동으로 검증한다.
  실제 테스트 서버(server/test_server.py)를 기동하여
  취약/안전 서버에 대한 탐지 정확도를 수치로 확인한다.

[실행 방법]
  cd <프로젝트 루트>
  python tests/test_integration.py

[테스트 환경]
  - Python 3.10+
  - requests 패키지 (DAST용)
  - 포트 9200에서 테스트 서버 자동 기동

[테스트 순서]
  PHASE 1 — 정적 분석 (SAST)
    1-1) vulnerable_webhook.py 분석 → 5가지 규칙(WHSEC-001~005) Finding 확인
    1-2) secure_webhook.py 분석 → Finding 0건 확인

  PHASE 2 — 테스트 서버 기동
    2-1) server/test_server.py를 포트 9200에서 daemon 스레드로 기동
    2-2) /health 또는 루트 경로로 서버 응답 확인

  PHASE 3 — Probe (Tier 분류)
    3-1) 6개 웹훅 엔드포인트 각각에 대해 Probe 실행
    3-2) 취약 엔드포인트가 Tier 1 또는 Tier 2로 분류되는지 확인
    3-3) /orders POST+GET 경로를 통한 Tier 1 상태 교차 검증 확인

  PHASE 4 — 동적 분석 (DAST 공격)
    4-1) 다운그레이드 공격: 취약 엔드포인트에서 vulnerable=True 확인
    4-2) 재전송 공격: no-timestamp 엔드포인트에서 vulnerable=True 확인
    4-3) 타입 혼동 공격: 전체 엔드포인트 대상 실행 및 결과 확인
    4-4) 안전 엔드포인트(/webhook/secure)는 모든 공격에서 vulnerable=False 확인

  PHASE 5 — 리포트 생성
    5-1) compute_endpoint_report / compute_full_report 실행
    5-2) 전체 등급(overall_grade)이 F 인지 확인 (취약 서버 기준)
    5-3) print_report 출력 확인

[엔드포인트-서명헤더 매핑 (SIG_MAP)]
  /webhook/no-verify       → X-Hub-Signature-256
  /webhook/timing-attack   → X-Hub-Signature-256
  /webhook/weak-hash-sha1  → X-Hub-Signature
  /webhook/weak-hash-md5   → X-Signature
  /webhook/no-timestamp    → X-Hub-Signature-256
  /webhook/secure          → X-Hub-Signature-256

[검증 헬퍼 함수]
  h1(title)          : 구분선 + 대제목 출력
  h2(title)          : 소제목 출력
  check(label, ok)   : ✅ / ❌ 체크 출력, bool 반환
"""

# TODO: sys.path 설정 (프로젝트 루트를 경로에 추가)
# TODO: 분석 모듈 import (engine, sast, dast, report, server.test_server)
# TODO: 상수 정의 (PORT, BASE URL, SAMPLES 경로, SIG_MAP, WEBHOOK_ENDPOINTS)
# TODO: 출력 헬퍼 함수 구현 (h1, h2, check)
# TODO: main() 함수 구현
#   PHASE 1: SAST 검증
#     - vulnerable_webhook.py → 각 규칙별 Finding 존재 여부 check()
#     - secure_webhook.py → Finding 0건 check()
#   PHASE 2: 테스트 서버 기동
#     - start_server(PORT) 호출
#     - 서버 응답 대기 (time.sleep 또는 재시도 루프)
#   PHASE 3: Probe Tier 분류 검증
#     - 각 엔드포인트별 ProbeResult.tier 확인
#   PHASE 4: DAST 공격 검증
#     - 각 공격 유형별 AttackResult.vulnerable 확인
#     - /webhook/secure 는 모두 False 확인
#   PHASE 5: 리포트 등급 확인
#     - overall_grade 출력
#     - 전체 통과/실패 집계 출력
# TODO: if __name__ == "__main__": 진입점
