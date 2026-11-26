"""분석 UI와 네 로컬 시연 스토어를 한 번에 실행한다. Ctrl+C로 함께 종료한다."""
import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

SERVERS = (
    ("HookLens 분석", "app:app", 8001),
    ("토스 형식 · DKU GOODS", "samples.shop_server:app", 8000),
    ("Stripe 형식 · FORM & FIELD", "samples.stripe_demo_server:app", 8002),
    ("Slack 알림 · COMMON TEAM", "samples.slack_demo_server:app", 8003),
    ("Generic · NEIGHBOR STORE", "samples.generic_shop_server:app", 8004),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-generic", action="store_true", help="선택 사항인 Generic 스토어는 실행하지 않음")
    args = parser.parse_args()
    selected = [row for row in SERVERS if not (args.without_generic and row[2] == 8004)]
    for name, _, port in selected:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                print(f"{port} 포트가 사용 중입니다 ({name}). 기존 실행을 종료하거나 개별 실행 명령을 사용하세요.", file=sys.stderr)
                return 2
    children = []
    try:
        for name, module, port in selected:
            command = [sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"]
            options = {"cwd": str(Path(__file__).parent)}
            if os.name == "nt":
                options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            process = subprocess.Popen(command, **options)
            children.append((name, process))
            print(f"{name}: http://127.0.0.1:{port}", flush=True)
        print("\n서버를 시작합니다. 위 주소를 브라우저에서 여세요. 종료: Ctrl+C", flush=True)
        while True:
            for name, process in children:
                if process.poll() is not None:
                    print(f"{name} 실행이 종료되었습니다 (코드 {process.returncode}). 의존성 설치와 오류 메시지를 확인하세요.", file=sys.stderr)
                    return 1
            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n시연 서버를 종료합니다.")
        return 0
    finally:
        for _, process in children:
            if process.poll() is None:
                process.terminate()
        for _, process in children:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    sys.exit(main())
