# WebhookFilter — 웹훅 핸들러 보안 취약점 자동 탐지 프레임워크

웹훅 수신 서버 개발자가 **배포 전** 자신의 핸들러 코드를 자가 검증할 수 있도록 설계된 SAST + DAST 하이브리드 보안 분석 도구입니다.

---

## 실행 환경

- **OS**: Ubuntu 22.04 (VMware Workstation Pro 기반 가상환경에서 개발 및 테스트)
- **Python**: 3.10
- **실행 방식**: 가상환경(venv) 기반

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 프로젝트 구조

```
webhook-analyzer/
├── main.py                        # CLI 진입점
├── app.py                         # Web UI / REST API 서버 (FastAPI)
│
├── analyzer/                      # 핵심 분석 패키지
│   ├── engine.py                  # AST 파서 + 라우트 추출 (코어 엔진)
│   ├── sast.py                    # 정적 분석 (SAST) — 5개 보안 규칙
│   ├── dast.py                    # 동적 분석 (DAST) — Probe + 3종 공격
│   ├── platform.py                # 플랫폼 자동 감지 (GitHub / Stripe 등)
│   ├── report.py                  # 통합 등급 결정 + 리포트 생성
│   ├── serializer.py              # 결과 객체 → JSON 변환
│   └── __init__.py
│
├── backend/
│   ├── upload.py                  # 파일 업로드 처리 + 임시 폴더 관리
│   └── __init__.py
│
├── frontend/
│   └── index.html                 # 웹 UI (단일 파일 SPA)
│
├── server/
│   ├── test_server.py             # 취약 / 안전 엔드포인트 내장 테스트 서버
│   └── __init__.py
│
├── samples/
│   ├── shop_server.py             # 시연용 서버 — 단국 굿즈샵 (토스페이먼츠 연동)
│   ├── vulnerable_webhook.py      # 취약 핸들러 예시 (SAST 규칙 검증용)
│   ├── secure_webhook.py          # 안전 핸들러 예시 (오탐 검증용)
│   ├── utils_vulnerable.py        # 외부 위임 취약 함수 (WHSEC-005 테스트용)
│   └── vulnerable_zip/            # zip 업로드 테스트용 패키지 구조 샘플
│
├── tests/
│   ├── test_integration.py        # 전체 파이프라인 E2E 통합 테스트
│   └── __init__.py
│
└── requirements.txt
```

---

## 시연 가이드 (Web UI)

WebhookFilter의 탐지 능력을 브라우저에서 직접 확인하는 방법입니다.  
터미널 2개가 필요합니다.

### 1단계 — 시연 대상 서버 실행

```bash
# 터미널 1
uvicorn samples.shop_server:app --port 8000 --reload
```

단국 굿즈샵 결제 서버가 `http://localhost:8000`에서 기동됩니다.

### 2단계 — WebhookFilter 서버 실행

```bash
# 터미널 2
uvicorn app:app --port 8001 --reload
```

### 3단계 — 브라우저에서 분석 실행

브라우저에서 `http://localhost:8001`에 접속한 뒤 아래 값을 입력합니다.

| 항목 | 입력값 |
|---|---|
| 소스코드 파일 | `samples/shop_server.py` 업로드 |
| 웹훅 URL | `http://localhost:8000` |
| 시크릿 키 | `dku-toss-secret-2026` |
| 상태 생성 경로 | `/orders` |
| 상태 조회 경로 | `/orders/{id}` |

분석 버튼을 누르면 SAST + DAST 전체 파이프라인이 실행되고, 엔드포인트별 취약점 등급과 수정 코드 스니펫이 표시됩니다.

> **주의:** 시크릿 키는 반드시 `dku-toss-secret-2026`을 입력해야 합니다.  
> 다른 값을 입력하면 DAST가 유효한 서명을 생성하지 못해 재전송 공격 탐지(WHSEC-004)가 실패합니다.
> 테스트 환경 구성을 위해 임의의 예시 키를 사용했습니다.

---

## 통합 테스트

전체 파이프라인(SAST → DAST → 등급 결정)이 정상 동작하는지 자동으로 검증합니다.  
**별도로 서버를 띄울 필요 없습니다.** 테스트 서버가 실행 중에 자동으로 기동되고, 테스트가 끝나면 자동으로 종료됩니다.

```bash
python tests/test_integration.py
```

아래 항목을 순서대로 검증합니다.

1. **SAST 검증** — `vulnerable_webhook.py` 분석 시 규칙별 Finding 건수 확인, `secure_webhook.py` 분석 시 0건(오탐 없음) 확인
2. **Probe** — 6개 엔드포인트 Tier 분류 확인
3. **DAST 공격** — 다운그레이드·재전송·타입 혼동 공격 실행 및 취약 판정 검증
4. **플랫폼별 검증** — Stripe, 토스페이먼츠, Slack, PortOne V2 엔드포인트 공격 검증
5. **등급 결정** — 전체 등급 F, SAST 7건+, DAST 4건+ 확인

모든 단계 통과 시 `🎉 전체 파이프라인 통과!`가 출력되고 종료 코드 0을 반환합니다.

---

## 파일별 역할 상세 설명

### 진입점

#### `main.py`
**CLI 진입점.** 터미널에서 직접 분석을 실행할 때 사용합니다.

- `argparse`로 `--code`, `--url`, `--secret`, `--state-create`, `--state-query` 등 인자를 처리합니다.
- 분석 파이프라인 5단계를 순서대로 호출합니다: AST 파싱 → 플랫폼 감지 → SAST → DAST → 리포트 출력.
- 취약점이 발견되면 종료 코드 1, 없으면 0을 반환하여 CI/CD 연동에 활용 가능합니다.

```bash
# 사용 예시 (SAST + DAST 통합 분석)
python main.py \
    --code samples/shop_server.py \
    --url  http://localhost:8000 \
    --secret dku-toss-secret-2026 \
    --state-create /orders \
    --state-query  /orders/{id}
```

---

#### `app.py`
**Web UI / REST API 서버.** FastAPI 기반으로, 브라우저에서 파일을 업로드하면 분석 결과를 JSON으로 반환합니다.

- `GET /` : `frontend/index.html`을 제공합니다.
- `GET /health` : 서버 상태 확인 엔드포인트입니다.
- `POST /analyze` : `.py` 또는 `.zip` 파일을 받아 SAST + DAST 전체 파이프라인을 실행하고 결과를 JSON으로 응답합니다.
- `main.py`와 분석 로직은 동일하지만, 다중 파일(zip) 업로드와 플랫폼별 공식 문서 링크 반환을 추가로 처리합니다.

```bash
# 실행 방법
uvicorn app:app --reload --port 8001
```

---

### `analyzer/` — 핵심 분석 패키지

#### `analyzer/engine.py`
**AST 파서 + 라우트 추출 (코어 엔진).** 다른 모든 분석 모듈이 이 파일의 결과를 기반으로 동작합니다.

- Python 소스코드를 `ast.parse()`로 파싱하여 **웹훅 핸들러**, **import 목록**, **라우트 정보**를 추출합니다.
- 웹훅 핸들러 판별 기준: 라우트 경로에 `webhook/hook/callback/notify/event` 키워드가 포함되거나, 함수 파라미터에 서명 헤더 변수명(`x_hub_signature_256`, `stripe_signature`, `tosspayments_webhook_signature` 등)이 있는 경우.
- `resolve_import()`: import된 외부 파일을 실제 `.py` 파일로 추적하여 `ParseResult`를 반환합니다 (SAST 규칙 5에서 사용).
- `_detect_router_split()`: `app.include_router()` 패턴을 감지하여 핸들러가 여러 파일에 분산된 경우 경고를 표시합니다.

**핵심 데이터 클래스:**

| 클래스 | 설명 |
|---|---|
| `ParseResult` | 파싱 결과 전체 (핸들러, 라우트, import, AST 트리 등) |
| `WebhookHandler` | 감지된 웹훅 핸들러 1개의 정보 |
| `RouteEndpoint` | 라우트 1개의 HTTP 메서드, 경로, 파라미터 정보 |

---

#### `analyzer/sast.py`
**정적 분석(SAST) 엔진.** `engine.py`의 `ParseResult`를 받아 5개의 보안 규칙을 적용하고 취약점(`Finding`)을 반환합니다.

| 규칙 ID | 취약점 | 심각도 | 설명 |
|---|---|---|---|
| WHSEC-001 | 서명 검증 누락 | CRITICAL (9.8) | HMAC 검증 로직 자체가 없는 경우 |
| WHSEC-002 | 타이밍 공격 (`==` 비교) | HIGH (7.4) | `==` 대신 `hmac.compare_digest`를 써야 함 |
| WHSEC-003 | 취약한 해시 알고리즘 | MEDIUM/CRITICAL | SHA1 (6.5) 또는 MD5 (9.1) 사용 탐지 |
| WHSEC-004 | 타임스탬프 검증 누락 | MEDIUM (5.9) | 재전송 공격 방어를 위한 타임스탬프 검증 부재 |
| WHSEC-005 | 외부 파일 위임 결함 | MEDIUM/CRITICAL | import한 외부 함수 내부의 취약점 추적 탐지 |

- 각 규칙은 `Finding` 객체와 함께 **자동 수정 코드 스니펫(`fix_snippet`)** 을 생성합니다.
- 5개 규칙은 플랫폼 구분 없이 동일하게 적용됩니다 (GitHub, Stripe, 토스페이먼츠 등 공통).

---

#### `analyzer/dast.py`
**동적 분석(DAST) 엔진.** 실제로 HTTP 요청을 보내어 런타임에서 취약점을 확인합니다.

**Probe (4단계 Tier 분류):**

| 단계 | 내용 |
|---|---|
| Step 1 | 서명 없이 전송 → 수락 여부 확인 |
| Step 2 | 잘못된 서명으로 전송 → 거부 여부 확인 |
| Step 3 | 유효한 서명으로 전송 → 정상 동작 확인 |
| Step 4 | 상태 조회 엔드포인트 존재 여부 → **Tier 1** / **Tier 2** 자동 분류 |

- **Tier 1** (상태조회 경로 입력 시): 공격 전후 DB 상태를 비교하여 높은 신뢰도로 판정
- **Tier 2** (미입력 시): HTTP 2xx 응답 여부만으로 판정

**3종 공격:**

| 공격 | 설명 |
|---|---|
| 다운그레이드 | SHA256 → SHA1 → MD5 → 서명 없음 순으로 알고리즘 다운그레이드 시도 |
| 재전송 | 만료된 타임스탬프(6분 전) + 유효한 서명으로 전송 |
| 타입 혼동 | Content-Type을 `text/plain`으로 변조 (Stage A), JSON을 배열로 래핑 (Stage B) |

**지원 플랫폼별 서명 형식:**

| 플랫폼 | 서명 형식 |
|---|---|
| GitHub | `X-Hub-Signature-256: sha256=<hex>` |
| Stripe | `Stripe-Signature: t=<ts>,v1=<hex>` |
| 토스페이먼츠 | `TossPayments-Webhook-Signature: <Base64(HMAC-SHA256)>` |
| Slack | `X-Slack-Signature: v0=<hex>` + `X-Slack-Request-Timestamp` 별도 헤더 |
| PortOne V2 | `webhook-signature: sha256=<hex>` |

---

#### `analyzer/platform.py`
**플랫폼 자동 감지 모듈.** 소스코드를 분석하여 어떤 웹훅 플랫폼인지 자동으로 판별하고, DAST에 사용할 서명 헤더 형식을 결정합니다.

**감지 방식 (우선순위 순):**

1. **파라미터 변수명**: 함수 인자에 `stripe_signature`, `x_hub_signature_256` 등이 있으면 확정 (신뢰도 HIGH)
2. **문자열 패턴**: 소스 전체에서 정규식 패턴 검색 (신뢰도 MEDIUM)
3. **Generic**: 일반적인 서명 헤더 추출 (신뢰도 LOW)

**지원 플랫폼:** `GitHub`, `Stripe`, `토스페이먼츠`, `Slack`, `PortOne V2`, `Generic`, `Unknown`

- `PLATFORM_DOC_LINKS`: 각 플랫폼의 공식 보안 가이드 링크를 포함합니다.
- `RULE_DOC_LINKS`: SAST 규칙별 참고 문서(OWASP, Python 공식 문서, NIST 등) 링크를 포함합니다.

---

#### `analyzer/report.py`
**통합 등급 결정 + 리포트 생성.** SAST와 DAST 결과를 합쳐 최종 보안 등급을 산출합니다.

- CVSS v3.1 점수를 기준으로 SAST Finding의 심각도를 합산합니다.
- SAST + DAST 모두 탐지 시 신뢰도 보정 (+0.5점, 최대 10.0).
- DAST만 탐지 시 CVSS 근거 없음 경고 표시.

**전체 등급 기준:**

| 등급 | 조건 |
|---|---|
| F | CRITICAL 취약점 존재 |
| D | HIGH 취약점 존재 |
| C | MEDIUM 취약점 존재 |
| B | LOW 취약점 존재 |
| A | 취약점 없음 |

**핵심 데이터 클래스:**

| 클래스 | 설명 |
|---|---|
| `EndpointReport` | 엔드포인트 1개의 SAST + DAST 통합 결과 |
| `FullReport` | 전체 파일에 대한 최종 리포트 |

---

#### `analyzer/serializer.py`
**결과 객체 → JSON 직렬화.** `app.py`의 API 응답에서 사용합니다.

- `finding_to_dict()`: SAST `Finding` → dict
- `attack_result_to_dict()`: DAST `AttackResult` → dict
- `probe_result_to_dict()`: `ProbeResult` → dict
- `full_report_to_dict()`: `FullReport` → dict (최종 API 응답 형식)

Python `dataclass` 객체를 FastAPI의 `JSONResponse`로 반환하기 위한 변환 계층입니다.

---

### `backend/`

#### `backend/upload.py`
**파일 업로드 처리 + 임시 폴더 관리.** `app.py`에서 호출하며, 업로드된 파일을 안전하게 임시 폴더에 저장합니다.

- `.py` 또는 `.zip` 파일만 허용 (최대 10MB).
- `_extract_zip()`: Zip Slip 방지 (`../` 경로 차단), Zip Bomb 방지 (압축 해제 누적 크기 50MB 제한, 64KB 청크 단위 스트리밍).
- `find_webhook_files()`: 추출된 `.py` 파일 목록에서 `webhook`, `app`, `main`, `server` 등 키워드가 포함된 파일을 우선 정렬합니다.
- `cleanup()`: 분석 완료 후 임시 폴더를 삭제합니다.

---

### `frontend/`

#### `frontend/index.html`
**웹 UI (단일 파일 SPA).** HTML + CSS + JavaScript가 하나의 파일에 통합되어 있습니다.

- 파일 업로드 폼(드래그 앤 드롭 지원)과 분석 결과 대시보드를 제공합니다.
- `POST /analyze` API를 호출하고 반환된 JSON을 파싱하여 엔드포인트별 SAST/DAST 결과를 시각적으로 표시합니다.
- WHSEC-004 참고 문서는 감지된 플랫폼에 맞는 공식 문서로 자동 전환됩니다 (토스페이먼츠 분석 시 토스페이먼츠 문서, Stripe 분석 시 Stripe 문서 등).
- 별도 빌드 과정 없이 `app.py` 서버가 그대로 서빙합니다.

---

### `server/`

#### `server/test_server.py`
**테스트 전용 웹훅 서버.** `tests/test_integration.py`에서 자동으로 기동합니다 (기본 포트 9000).

**취약 엔드포인트 (의도적으로 결함 포함):**

| 경로 | 취약점 |
|---|---|
| `POST /webhook/no-verify` | 서명 검증 자체 없음 (WHSEC-001) |
| `POST /webhook/timing-attack` | `==` 비교 (WHSEC-002) |
| `POST /webhook/weak-hash-sha1` | SHA1 사용 (WHSEC-003) |
| `POST /webhook/weak-hash-md5` | MD5 사용 (WHSEC-003) |
| `POST /webhook/no-timestamp` | 타임스탬프 검증 없음 (WHSEC-004) |
| `POST /webhook/stripe` | Stripe 형식, 타임스탬프 미검증 |
| `POST /webhook/toss` | 토스페이먼츠 형식, `==` 비교 |
| `POST /webhook/slack` | Slack 형식, 타임스탬프 미검증 |
| `POST /webhook/portone` | PortOne V2 형식, 서명 검증 누락 |

**안전 엔드포인트:**

| 경로 | 설명 |
|---|---|
| `POST /webhook/secure` | SHA256 + `compare_digest` + 타임스탬프 + 타입 검증 모두 적용 |

**상태 교차 검증용 (Tier 1):**

| 경로 | 설명 |
|---|---|
| `POST /orders` | 주문 생성 (응답에 `order_id` 포함) |
| `GET /orders/{id}` | 주문 상태 조회 |

---

### `samples/`

#### `samples/shop_server.py` ← 주 시연 대상
**단국 굿즈샵 — 토스페이먼츠 결제 연동 서버 (시연용).** WebhookFilter의 탐지 능력을 직접 확인하기 위한 데모 서버입니다.

"개발은 다 됐는데 보안 문제는 없을까?" 라는 상황을 가정하며, 의도적으로 두 가지 취약점이 삽입되어 있습니다.

| 취약점 | 내용 |
|---|---|
| WHSEC-002 HIGH | 서명 비교에 `==` 사용 (타이밍 공격 취약) |
| WHSEC-004 MEDIUM | `toss-timestamp` 헤더를 수신하지만 만료 검증 미실시 |

#### `samples/vulnerable_webhook.py`
**취약 핸들러 예시 파일.** SAST 규칙 검증용 코드입니다.

- WHSEC-001 ~ WHSEC-005 각각에 대응하는 취약 핸들러가 포함되어 있습니다.
- `utils_vulnerable.py`에서 결함 있는 함수를 import하여 외부 파일 위임 탐지(WHSEC-005)도 시연합니다.

#### `samples/secure_webhook.py`
**안전 핸들러 예시 파일.** 오탐(False Positive) 검증용 코드입니다.

- `hmac.compare_digest` + SHA256 + 타임스탬프 검증이 모두 올바르게 구현되어 있습니다.
- SAST 분석 시 Finding 0건이 나와야 정상입니다.

#### `samples/utils_vulnerable.py`
**외부 위임 취약 함수.** WHSEC-005 탐지 테스트용 보조 파일입니다.

- `verify_signature()` 함수 내부에서 `==` 비교를 사용합니다.
- `vulnerable_webhook.py`에서 import하며, SAST가 이 파일까지 추적하여 내부 결함을 탐지합니다.

#### `samples/vulnerable_zip/`
**zip 업로드 테스트용 샘플 패키지.**  

업로드 엔드포인트는 파일을 하나만 받을 수 있기 때문에, 여러 파일로 구성된 프로젝트는 zip으로 묶어서 올려야 합니다. vulnerable_shop_server.py만 단독으로 올리면 from webhook_utils import audit_signature 라인에서. 파일을 추적할 수 없어 WHSEC-005가 탐지되지 않습니다. 두 파일을 zip으로 묶으면 upload.py가 압축을 풀고 engine.py가 import를 따라가 내부 결함까지 탐지합니다.  

이 디렉터리는 그 시나리오를 바로 테스트할 수 있도록 준비된 샘플입니다.

---

### `tests/`

#### `tests/test_integration.py`
**전체 파이프라인 E2E 통합 테스트.** 위 [통합 테스트](#통합-테스트) 섹션을 참고하세요.

---

## 분석 파이프라인 흐름

```
사용자 입력 (소스코드 파일 + 웹훅 URL)
              │
              ▼
        [1] engine.py
    AST 파싱 → ParseResult 생성
              │
              ▼
       [2] platform.py
  플랫폼 감지 → 서명 헤더 / 형식 결정
              │
       ┌──────┴──────┐
       ▼             ▼
  [3] sast.py   [4] dast.py
  5개 규칙 적용  Probe + 3종 공격
  Finding 생성   AttackResult 생성
       │             │
       └──────┬──────┘
              ▼
        [5] report.py
    CVSS 등급 산정 + 통합 리포트
              │
              ▼
      [6] serializer.py
    JSON 직렬화 → API 응답
```

---

## 실행 방법 요약

| 방법 | 명령 |
|---|---|
| 시연 서버 실행 | `uvicorn samples.shop_server:app --port 8000 --reload` |
| Web UI 서버 실행 | `uvicorn app:app --reload --port 8001` |
| CLI 분석 | `python main.py --code samples/shop_server.py --url http://localhost:8000 --secret dku-toss-secret-2026 --state-create /orders --state-query /orders/{id}` |
| 통합 테스트 | `python tests/test_integration.py` |
| 테스트 서버 단독 실행 | `python server/test_server.py` (포트 9000) |
