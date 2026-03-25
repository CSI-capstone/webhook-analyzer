"""
backend/upload.py — 파일 업로드 처리 모듈

[역할]
  클라이언트가 업로드한 .py 또는 .zip 파일을 받아
  분석 가능한 형태로 변환하고 임시 폴더에 저장한다.

[처리 흐름]
  1) 파일 크기 검증 (최대 10MB)
  2) 확장자 검증 (.py 또는 .zip 만 허용)
  3) 임시 디렉터리 생성 (tempfile.mkdtemp)
  4) .zip 이면 압축 해제, .py 이면 그대로 저장
  5) 분석 대상 .py 파일 목록 반환
  6) 분석 완료 후 cleanup() 으로 임시 폴더 삭제

[보안 고려사항]
  - Zip Slip 방지: 압축 내 파일 경로에 ../ 가 포함된 항목은 건너뜀
  - 압축 해제 후 .py 파일만 추출 (다른 확장자는 무시)
  - 업로드 허용 확장자와 분석 허용 확장자를 별도 상수로 분리

[상수]
  MAX_FILE_SIZE           : 10MB
  ALLOWED_EXTENSIONS      : {".py"} — 분석 대상
  ALLOWED_UPLOAD_EXTENSIONS : {".py", ".zip"} — 업로드 허용

[공개 함수]
  process_upload(file_bytes, filename) → (tmp_dir, py_files)
    파일을 임시 폴더에 저장하고 .py 파일 목록 반환

  find_webhook_files(py_files) → py_files
    업로드된 .py 파일 중 웹훅 핸들러가 있을 법한 파일 우선 정렬
    (향후 확장: 웹훅 관련 키워드가 있는 파일만 필터링)

  cleanup(tmp_dir)
    임시 디렉터리를 안전하게 삭제 (shutil.rmtree, ignore_errors=True)

[예외]
  UploadError(Exception) : 파일 처리 실패 시 발생
    - 파일 크기 초과
    - 지원하지 않는 확장자
    - zip 압축 해제 실패
    - 분석 가능한 .py 파일 없음
"""

# TODO: 상수 정의 (MAX_FILE_SIZE, ALLOWED_EXTENSIONS, ALLOWED_UPLOAD_EXTENSIONS)
# TODO: UploadError 예외 클래스 정의
# TODO: process_upload() 구현
#   - 크기 / 확장자 검증
#   - 임시 폴더 생성
#   - zip / py 분기 처리
#   - 실패 시 임시 폴더 정리 후 UploadError raise
# TODO: _extract_zip() 내부 함수 구현
#   - Zip Slip 방지 로직
#   - .py 파일만 추출
# TODO: find_webhook_files() 구현
# TODO: cleanup() 구현
