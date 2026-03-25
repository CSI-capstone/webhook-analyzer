"""
main.py — CLI 진입점

[역할]
  터미널에서 직접 분석을 실행할 수 있는 CLI 인터페이스.
  app.py(웹 API)와 동일한 분석 파이프라인을 사용하되, argparse로 인자를 받는다.

[사용법]
  python main.py \\
      --code <python_file_or_zip> \\
      --url  <webhook_base_url>   \\
      [--state-create  <path>]       예: /orders
      [--state-query   <template>]   예: /orders/{id}
      [--secret        <secret_key>] \\
      [--sast-only]                  # DAST 건너뜀
      [--dast-only]                  # SAST 건너뜀

[파이프라인]
  1) argparse 인자 파싱 및 유효성 검사
  2) analyzer/platform.py 로 플랫폼 자동 감지
  3) analyzer/sast.py 로 정적 분석 (--dast-only 가 아닌 경우)
  4) analyzer/dast.py 로 동적 분석 (--sast-only 가 아니고 --url 이 있는 경우)
       - Probe → Tier 1/2/3 자동 결정
       - 다운그레이드 / 재전송 / 타입 혼동 공격 순서로 실행
  5) analyzer/report.py 로 통합 리포트 생성 및 터미널 출력

[종료 코드]
  0 : 취약점 없음
  1 : 취약점 발견
  2 : 입력 오류 (파일 없음, URL 잘못됨 등)
"""

# TODO: argparse 파서 정의 (build_parser 함수)
# TODO: 파이프라인 실행 함수 구현 (run 함수)
#   - 파일 존재 여부 확인
#   - 각 분석 모듈 순서대로 호출
#   - 결과를 print_report 로 터미널 출력
# TODO: if __name__ == "__main__": 진입점
#   - 파싱 실패 / 파일 없음 등 예외 처리
#   - 취약점 발견 여부에 따라 종료 코드 결정
