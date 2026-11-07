# HookLens

Python 웹훅 수신 핸들러를 배포 전에 점검하는 정적·동적 분석 도구이다.
기존 **SAST 5개 규칙 + DAST 3개 시나리오**와 AST → 플랫폼 감지 → SAST/DAST → 리포트 흐름을 유지한다.

상세 변경 내용과 수정 전후 예시는 [코드 보완 설명](docs/CODE_CHANGES.md)을 참고한다.
UI 레퍼런스·변경 파일·시연 순서와 최신 검증은 [UI 개편 설명](docs/UI_CHANGES.md)을 참고한다.

## 설치와 실행

Python 3.10 이상을 사용한다. 업로드된 Python 코드를 import하거나 실행하지 않고 AST로 읽는다.
DAST는 사용자가 별도로 실행한 자신의 테스트 서버로 요청을 보낸다.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --port 8001
```

Windows에서는 `.venv\Scripts\activate`로 가상환경을 활성화한다.
브라우저에서 `http://127.0.0.1:8001`을 연다.
웹훅 URL을 비우면 정적분석만 수행한다.

```bash
# 일반 HMAC 모의 쇼핑몰: 실제 결제 제공자 연동 예제가 아니다.
uvicorn samples.shop_server:app --port 8000

# 정적분석만
python main.py --code samples/vulnerable_webhook.py --sast-only

# 정적·동적 분석
python main.py --code samples/shop_server.py \
  --url http://127.0.0.1:8000 --secret dku-toss-secret-2026 \
  --state-create /orders --state-query '/orders/{id}'
```

시연용 키 이름은 기존 실행 예시와의 호환을 위해 유지했다. 실제 토스 결제용 키가 아니다.

## 점검 규칙

| ID | 내용 |
|---|---|
| WHSEC-001 | 지원하는 서명 검증·실패 거부 패턴을 찾지 못함 또는 검증 확인 불가 |
| WHSEC-002 | 서명에 일반 동등·부등 비교 사용 |
| WHSEC-003 | HMAC-SHA1/MD5 사용 및 SHA256 정책 검토 |
| WHSEC-004 | 수신 시간값의 유효성 검증 누락 |
| WHSEC-005 | 외부 파일의 검증 함수 내부 결함 또는 소스 추적 불가 |

005는 외부 위임 자체를 취약점으로 간주하지 않는다. 외부에서 찾은 비교·해시 결함을 보고한다.
동적 import 안내 `WHSEC-DYN`은 기존의 보조 INFO 안내이며 여섯 번째 보안 규칙이 아니다.

AST 분석은 한정된 패턴을 인식한다. 변수·함수명만으로 검증 성공을 인정하지 않도록 개선했지만,
임의의 Python 프로그램 전체에 대한 데이터 흐름·모든 실행 경로를 증명하지는 않는다.

## 동적분석과 결과 해석

Probe는 서명 누락 → 잘못된 서명 → 정상 서명 → 상태 조회 가능 여부의 4단계를 유지한다.
정상 서명 요청이 2xx로 응답하지 않으면 공격 실패를 안전으로 해석하지 않는다.

| 상태 | 의미 |
|---|---|
| `vulnerable` | 선언한 시험 정책을 위반한 요청과 해당 시험 주문 상태 변경을 함께 관측 |
| `rejected` | 정상 요청 기준선이 성립한 상태에서 시험 요청이 거부됨. 시험 범위 내 결과 |
| `observed` | 수락을 관측했으나 처리 효과·정책 위반 근거가 충분하지 않음 |
| `inconclusive` | 정상 요청 실패, 연결 오류, 5xx, 429, 리다이렉트 등으로 판단 불가 |
| `skipped` | 시크릿 미입력 또는 해당 프로토콜에 시험을 적용할 수 없음 |

기존 `vulnerable: bool`도 유지하며, 확정된 처리 증거가 있는 결과만 `true`이다.
등급 A는 **지원하는 점검 범위 내 미탐지**라는 뜻이다. 전체 보안 보증이 아니다.
미완료·미확정 항목이 있으면 A 대신 N/A를 사용한다(이미 탐지된 위험이 있으면 위험 등급과 partial 상태를 함께 표시).

DAST 3종은 다음과 같다.

1. **다운그레이드/서명 정책**: 일반 HMAC·GitHub 형식에는 SHA1/MD5 및 서명 누락을 시험한다.
   알고리즘 선택 문법이 없는 Stripe·Slack·토스·PortOne에는 잘못된 서명/서명 누락을 시험한다.
   GitHub 레거시 SHA1 헤더 수락은 정책 확인이 필요하므로 관측으로 보고한다.
2. **재전송**: 대상 허용 시간보다 60초 오래된 시간값과 유효 서명을 보낸다.
   가능한 프로토콜에는 본문·서명을 그대로 둔 시간 헤더 갱신도 시험한다.
   GitHub의 전달 ID 중복 방지는 이 시간 기반 시험에서 검증하지 않는다.
3. **타입 혼동/입력 정책**: `text/plain`, JSON 배열 래핑을 시험한다.
   기본은 수락 관측이다. 대상이 JSON 객체만 허용한다는 계약이 있을 때만 `--strict-json` 또는 UI 체크박스를 선택한다.
   유효한 서명으로 보내므로 인증 우회 성공을 뜻하지 않는다.

`--timestamp-tolerance 300` 또는 UI 입력으로 대상의 실제 허용 시간을 설정한다.
CLI 종료 코드는 0(점검 범위 미탐지), 1(위험 징후/처리 증거 탐지), 2(입력 오류·분석 미완료)이다.

## 상태 조회 인터페이스

Tier 1은 시험 생성·조회 API가 있어 결과를 관측할 수 있다는 뜻이다. 취약 확정과 동의어가 아니다.

- 생성: 지정 경로에 `POST {"item":"analyzer_test"}`. 2xx JSON 응답의 `order_id`, `id`, `pk` 중 하나를 사용한다.
- 조회: 경로 템플릿의 `{id}`를 치환해 GET. JSON의 `status` 또는 `state`를 읽는다.
- 각 시험에서 새 주문을 만들고 전후 값을 비교한다. 조회 실패는 상태 변경으로 인정하지 않는다.
- 생성된 시험 주문을 서버가 실제 이벤트의 대상과 연결할 수 있어야 한다. 예제는 보조 `order_id` 필드로 연결한다.

실제 서비스의 스키마·인증·업무 처리가 예제와 다르면 어댑터 조정이 필요하다. 정상 기준 요청 실패로 드러나며 안전 판정을 내리지 않는다.
시험은 주문 생성 등 상태 변경을 유발하므로 실제 운영 결제 서버가 아닌 자신이 관리하는 테스트 환경에서 실행한다.

## 플랫폼 지원 범위

| 플랫폼 | 생성하는 서명 형식 |
|---|---|
| GitHub | `sha256=` + HMAC-SHA256(raw body), 이벤트/전달 ID 헤더 |
| Stripe | `t=<ts>,v1=<hex>`, `ts.body`를 서명 |
| Slack | `v0=<hex>`, `v0:ts:body`를 서명, 별도 시간 헤더 |
| 토스페이먼츠 | 서명이 제공되는 `payout.changed` 모의 이벤트. `body:transmission-time` 서명, `v1:<Base64>` |
| PortOne V2 | Standard Webhooks: Base64 디코딩 키, `id.ts.body` 서명, `v1,<Base64>` |

PortOne에는 발급된 `whsec_...` 또는 Base64 시크릿을 입력한다.
토스 일반 결제 `PAYMENT_STATUS_CHANGED`에는 동일한 서명 정책을 강제하지 않는다.
일반 결제의 결제 조회 API 검증은 본 도구의 현재 자동 점검 범위 밖이다.
한 번의 실행에는 시크릿 하나를 사용하므로 실제 플랫폼마다 키가 다르면 따로 분석한다.
공식 서비스와의 실시간 상호운용성 인증을 의미하지 않으며, 모의 이벤트 스키마는 실제 업무에 맞춰 조정해야 한다.

## 출력 점수

`cvss_score`와 `overall_cvss` 키는 기존 JSON 호환을 위해 유지한다.
표시는 **규칙 참고 위험도**이며, 환경별 CVSS 벡터를 산출한 공식 CVSS 점수는 아니다.
정적·동적 탐지가 함께 있어도 점수에 0.5를 더하지 않는다.
HMAC-MD5는 충돌 문제만으로 즉시 서명 위조가 입증되었다고 판단하지 않으며 MEDIUM으로 조정했다.
DAST 단독 탐지에도 위험 등급을 반영하되 근거 없는 숫자 CVSS를 만들지 않는다.

## 테스트

```bash
python -m unittest discover -s tests -v
python tests/test_integration.py
# 선택적 프런트엔드 JS 렌더링 함수 검사(Node.js 필요; 제품 실행에는 불필요)
node tests/check_frontend.cjs
```

단위·회귀 테스트는 Python 표준 `unittest`를 사용한다.
실제 ASGI/multipart 검사(`test_http_api.py`) 6개는 프로젝트 의존성과 `pip install httpx`가 있을 때 실행된다. 없으면 해당 모듈만 생략한다.
`test_api_pipeline.py`는 FastAPI가 없으면 선언 인터페이스 대역으로 실제 분석 함수를 시험한다.
이 경우 ASGI/HTTP 라우팅 검증은 아니다. FastAPI 설치 환경에서는 실제 모듈을 사용한다.
이 보완 작업의 실행 환경과 검증 한계는 `docs/CODE_CHANGES.md`에 기록했다.

## 남은 제한

- FastAPI/Flask의 일부 데코레이터와 헤더 읽기 패턴을 인식한다. Django 전체, 동적 라우트, 모든 SDK·의존성 주입은 지원하지 않는다.
- 동일 파일 호출 최대 4단계, 외부 파일 추적 1단계. 순환 호출은 중복 방문을 중단한다.
- `include_router`/Blueprint prefix와 등록 관계를 자동 합성하지 않는다. 중복 경로·미치환 경로 파라미터·POST 외 메서드는 자동 DAST를 확정하지 않는다.
- 상태 조회는 일반적인 JSON 계약만 지원한다. 비동기 처리 대기 이후에도 변화가 없으면 미확정으로 남는다.
- 업로드 크기와 ZIP 누적 해제 크기를 제한하지만 대규모 소스의 CPU/메모리를 별도 샌드박스로 격리하지 않는다.
- 분석 API의 인증·다중 사용자 작업 큐·운영 배포 보안 강화는 이번 보완 범위에 포함하지 않는다.
