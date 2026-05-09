"""
backend/upload.py

업로드 파일 처리 — zip 압축 해제 + 임시 폴더 관리

흐름:
  1) .zip 또는 .py 파일 바이트를 받아서 임시 폴더에 저장
  2) zip이면 압축 해제, .py면 그대로 저장
  3) 압축 해제된 폴더에서 .py 파일 목록 반환
  4) 분석 완료 후 cleanup() 으로 임시 폴더 삭제

보안:
  - zip slip 방지 (경로에 ../ 포함된 항목 건너뜀)
  - .py 파일만 추출 허용
  - 최대 파일 크기: 10MB
"""

import io
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Tuple


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".py"}          # 압축 해제 후 분석 대상 확장자
ALLOWED_UPLOAD_EXTENSIONS = {".py", ".zip"}  # 버그 19 수정: 업로드 허용 확장자 상수 분리


class UploadError(Exception):
    pass


def process_upload(file_bytes: bytes, filename: str) -> Tuple[str, List[str]]:
    """
    업로드 파일을 처리하여 임시 폴더 경로와 .py 파일 목록을 반환.

    Args:
        file_bytes: 업로드된 파일의 바이트
        filename:   원본 파일명 (.py 또는 .zip)

    Returns:
        (tmp_dir, py_files)
          tmp_dir  : 임시 폴더 경로 (분석 후 cleanup() 호출 필요)
          py_files : 분석 대상 .py 파일의 절대 경로 목록
    """
    if len(file_bytes) > MAX_FILE_SIZE:
        raise UploadError(f"파일 크기 초과: {len(file_bytes) // 1024}KB (최대 10MB)")

    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:  # 버그 19 수정: 상수 사용
        raise UploadError(f"지원하지 않는 파일 형식: {ext} (.py 또는 .zip 만 허용)")

    tmp_dir = tempfile.mkdtemp(prefix="webhook_analyzer_")

    try:
        if ext == ".zip":
            py_files = _extract_zip(file_bytes, tmp_dir)
        else:
            safe_name = Path(filename).name  # 경로 구분자 제거
            dest = os.path.join(tmp_dir, safe_name)
            with open(dest, "wb") as f:
                f.write(file_bytes)
            py_files = [dest]
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise UploadError(f"파일 처리 실패: {e}") from e

    if not py_files:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise UploadError("분석 가능한 .py 파일이 없습니다.")

    return tmp_dir, py_files


def _extract_zip(file_bytes: bytes, dest_dir: str) -> List[str]:
    """zip 파일을 dest_dir에 압축 해제하고 .py 파일 목록 반환."""
    # 버그 10 수정: 압축 해제 후 총 크기를 추적하여 zip bomb 방어
    MAX_EXTRACT_SIZE = 50 * 1024 * 1024  # 50MB
    total_extracted = 0

    py_files = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            for member in zf.infolist():
                # zip slip 방지: 경로에 ../ 포함된 항목 건너뜀
                member_path = Path(member.filename)
                if ".." in member_path.parts:
                    continue
                # 디렉터리는 건너뜀
                if member.filename.endswith("/"):
                    continue
                # .py 파일만 추출
                if member_path.suffix.lower() != ".py":
                    continue

                # 대상 경로 생성
                target = os.path.join(dest_dir, member.filename)
                os.makedirs(os.path.dirname(target), exist_ok=True)

                # 버그 1 수정: src.read() 전체 읽기 → 청크 단위 스트리밍으로 변경
                # 이유 A: member.file_size는 zip 헤더 메타데이터라 공격자가 조작 가능
                #         → 실제 읽은 바이트 수를 직접 누적해야 진짜 방어가 됨
                # 이유 B: 전체를 한 번에 read()하면 대용량 파일 시 OOM 위험
                CHUNK_SIZE = 64 * 1024  # 64KB 단위
                with zf.open(member) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        total_extracted += len(chunk)
                        if total_extracted > MAX_EXTRACT_SIZE:
                            raise UploadError(
                                f"압축 해제 크기 50MB 초과 — zip bomb 의심 "
                                f"(누적: {total_extracted // 1024 // 1024}MB)"
                            )
                        dst.write(chunk)
                py_files.append(target)
    except zipfile.BadZipFile:
        raise UploadError("올바른 zip 파일이 아닙니다.")

    return py_files


def find_webhook_files(py_files: List[str]) -> List[str]:
    """
    .py 파일 목록에서 웹훅 핸들러가 포함된 파일을 우선 정렬.
    파일명에 'webhook', 'hook', 'handler', 'app', 'main' 이 포함된 파일이 앞으로.
    """
    PRIORITY_KEYWORDS = {"webhook", "hook", "handler", "app", "main", "server"}

    def priority(path: str) -> int:
        name = Path(path).stem.lower()
        return 0 if any(kw in name for kw in PRIORITY_KEYWORDS) else 1

    return sorted(py_files, key=priority)


def cleanup(tmp_dir: str):
    """임시 폴더 삭제. 분석 완료 후 반드시 호출."""
    if tmp_dir and os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)
