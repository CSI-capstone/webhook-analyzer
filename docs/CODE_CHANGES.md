# HookLens 코드 보완 설명서

> 이 문서는 최초 내부 로직 보완 단계의 기록이다. 후속 UI 개편과 최신 검증은 [UI 개편 설명서](UI_CHANGES.md)를 참고한다.

작성일: 2026-10-20  
기준 원본: `webhook-analyzer-main (5).zip` (동일 내용의 `(5)(1).zip` 포함)  
원본 ZIP SHA-256: `b13984a1580967830766629275c8c6499fdc2456aedeb889bb499ec532b3a28a`

## 1. 보완 목적과 유지한 범위

이번 보완은 기존 분석 방식의 판정 오류를 줄이는 작업이다. 새로운 분석 엔진으로 교체하지 않았다.

| 항목 | 보완 후 |
|---|---|
| 지원 언어 | Python 유지 |
| 정적분석 | WHSEC-001~005의 5개 규칙 유지 |
| 동적분석 | 다운그레이드·재전송·타입 혼동 3개 공격군 유지 |
| 분석 흐름 | AST 파싱 → 플랫폼 감지 → SAST/DAST → 통합 리포트 유지 |
| 입력 | `.py` / `.zip` + 별도 실행 중인 테스트 서버 URL 유지 |
| 관측 수준 | Tier 1 상태 조회 / Tier 2 HTTP 관측 유지 |
| 플랫폼 | GitHub·Stripe·토스페이먼츠·Slack·PortOne V2 유지 |
| 결과 제공 | 웹 화면, CLI, 수정 참고 예제 유지 |

정적분석이 업로드 코드를 실행하거나, DAST가 업로드 프로젝트를 자동으로 서버로 띄우지는 않는다.
기존 `WHSEC-DYN`은 동적 import에 대한 INFO 안내로 유지했으며 새 보안 규칙으로 세지 않는다.

포스터의 기존 결과는 원래 테스트 사례와 버전의 결과로 구분한다. 이번 보완의 결과 수치를 그 숫자에 억지로 맞추지 않았다.

## 2. 우선 해결한 문제

| 보완 전 | 보완 후 |
|---|---|
| HMAC를 계산만 해도 검증이 있다고 간주할 수 있음 | 비교 결과가 지원하는 거부/반환 분기와 연결되는지 확인 |
| 이름에 verify가 있으면 구현을 신뢰할 수 있음 | 추적 가능한 함수 내부를 확인. 미추적 검증은 INFO·부분 분석 |
| 시간 출력만 있어도 시간 검증으로 볼 수 있음 | 현재 시간과 수신 시간값의 비교 및 처리 분기 확인 |
| `digestmod=hashlib.md5`, import 별칭 등을 놓침 | 키워드 인자, 문자열 알고리즘, 별칭 정규화 지원 |
| 모든 HTTP 비성공을 공격 거부·안전으로 볼 수 있음 | 500·429·연결 오류·302 등을 판단 불가로 구분 |
| 잘못된 시크릿인데도 방어 정상으로 표시 가능 | 정상 서명 기준 요청이 먼저 성공해야 공격 결과 해석 |
| 2xx 수락 자체를 취약 확정으로 집계 | 처리 상태 변경이 없으면 수락 관측으로 분리 |
| 타입/배열 수락을 무조건 취약으로 표시 | 기본은 관측. 명시한 JSON 객체 전용 정책이 있을 때만 위반 평가 |
| 외부 함수 Finding이 SAST-only 결과에서 누락될 수 있음 | 원래 핸들러 위치와 결함 파일 위치를 별도로 보존해 연결 |
| 한 플랫폼 설정을 모든 엔드포인트에 적용 | 핸들러별 플랫폼·서명 헤더·서명 방식 적용 |
| DAST 단독 탐지가 있어도 A 등급 가능 | 동적 처리 증거도 심각도와 최종 등급에 반영 |
| 다른 결함끼리도 교차 확인으로 표시 | 관련 규칙 ID가 일치하는 증거만 교차 확인 |
| 교차 탐지 시 CVSS +0.5 | 가산 제거. 참고 위험도와 탐지 증거를 분리 |

## 3. 파일별 변경 목록

기존 파일 17개를 수정하고, 보조 모듈·테스트 파일 5개를 추가했다. 나머지는 설명 문서와 검증 기록이다.
정확한 원본 대비 차이는 `docs/changes.patch`에서도 확인할 수 있다.

| 파일 | 핵심 변경 |
|---|---|
| `analyzer/engine.py` | 상대 import, 별칭 해석에 필요한 정보, ZIP 상위 래퍼 탐색, 헤더 읽기·Header alias·keyword-only 인자 인식, 소스 읽기 오류 처리 |
| `analyzer/ast_checks.py` **추가** | 기존 5개 규칙이 공통으로 사용하는 제한적 호출 추적·조건 확인 |
| `analyzer/sast.py` | 기존 5개 규칙의 판정 조건, 비교 수정 예제, 해시 탐지, 외부 결함 위치 정보 |
| `analyzer/dast.py` | 5가지 결과 상태, 정상 요청 기준선, 증거 확인, 플랫폼별 서명·시간 처리, 개별 시험 주문 |
| `analyzer/platform.py` | 핸들러별 플랫폼 감지, 실제 헤더 alias 반영, Tier 설명과 참고 링크 정정 |
| `analyzer/report.py` | DAST 단독 등급, 동일 항목 교차 확인, 부분 분석 표시, 외부 결과 그룹핑 |
| `analyzer/serializer.py` | 기존 JSON 키 유지 + 상태·변형·관련 규칙·원래 핸들러 경로·분석 상태 추가 |
| `app.py` | 핸들러별 DAST 설정, SAST-only 외부 결과 누락 수정, 파싱 오류 표시, 중복/미지원 경로 보류, 추가 설정 |
| `main.py` | 웹 API와 동일한 상태 해석·그룹핑·플랫폼별 설정, 입력 검증·종료 코드 보완 |
| `backend/upload.py` | ZIP 절대 경로·Windows 경로·심볼릭 링크 차단, 해제 경계·항목 수 제한 |
| `frontend/index.html` | 미확정 결과를 초록색 안전으로 표시하지 않음, 기준선·관측 수·경고 표시, 선택 설정 |
| `server/test_server.py` | 서명된 본문 시간 검사, 실제 다운그레이드용 강한/약한 방식 동시 허용 예제, Toss 시험 형식 정정 |
| `samples/secure_webhook.py` | 일반 HMAC 예제 헤더를 X-Signature로 구분, 본문의 서명된 시간값 검증 |
| `samples/vulnerable_webhook.py` | 일반 HMAC 헤더 구분, SHA256 기준 요청도 받는 다운그레이드 결함 표현, 해시 설명 정정 |
| `samples/shop_server.py` | 실제 토스 결제 연동이 아닌 모의 HMAC 쇼핑몰로 정정 |
| `samples/vulnerable_zip/vulnerable_shop_server.py` | 같은 모의 서비스 표현과 헤더 명칭 반영 |
| `tests/test_integration.py` | 새 판정 상태 검증, 플랫폼 시크릿 형식, 임의 포트·세션 정리 |
| `tests/test_regressions.py` **추가** | 정적·동적 판정 반례, 서명 벡터, 등급·업로드 회귀 시험 |
| `tests/test_api_pipeline.py` **추가** | 실제 analyze 함수의 다중 파일·플랫폼·결과 연결 시험 |
| `tests/test_cli.py` **추가** | CLI 입력 검증과 종료 코드 |
| `tests/check_frontend.cjs` **추가** | 실제 JavaScript 렌더링 함수의 상태 표시·HTML escaping 검사 |
| `README.md` | 실행 방법, 변경된 결과 의미, 플랫폼 범위, 제한 사항 갱신 |

## 4. AST 엔진과 보조 모듈

### `engine.py`

- `ImportInfo.level`로 `from .security import check`와 같은 상대 import 정보를 보존한다.
- `resolve_import()`는 현재 디렉터리부터 지정 프로젝트 루트까지 탐색한다. ZIP의 최상위 래퍼 폴더 때문에 모듈을 못 찾던 경우를 줄였다.
- 해석한 파일 경로가 프로젝트 경계 밖으로 나가면 읽지 않는다.
- `request.headers.get("Stripe-Signature")`처럼 본문에서 헤더를 읽는 핸들러도 경로 이름만으로 누락하지 않는다.
- `Header(alias="...")`, keyword-only 헤더 인자를 인식한다.
- Flask `methods=['GET','POST']`는 POST 점검 대상으로 인식한다.
- `tokenize.open()`으로 소스 인코딩을 읽고, 잘못된 인코딩/읽기 실패는 파싱 오류로 반환한다.

### `ast_checks.py`

기존 SAST에서 중복되던 호출·비교 확인을 보조 모듈로 모았다.

- import 별칭을 정규화한다: `hm.new` → `hmac.new`, `weak` → `hashlib.md5`.
- 직접 호출, 같은 파일의 보조 함수, 외부 모듈 함수 호출을 해석한다.
- 같은 파일의 호출은 최대 4단계, 외부 파일 이동은 원래와 같이 1단계로 제한한다.
- 순환 호출은 방문 집합으로 중단한다. 업로드 코드를 import/실행하지 않는다.
- 검증 실패 시 조건이 어떤 값을 가질 수 있는지 제한적으로 확인한다. `if valid: raise` 같은 뒤집힌 조건, `bypass or valid`, 죽은 거부 조건을 검증으로 신뢰하지 않도록 했다.

이것은 범용 제어 흐름 그래프나 완전한 데이터 흐름 분석이 아니다. 복잡한 예외 처리·데코레이터·동적 디스패치·임의 조건까지 안전성을 증명하지 않는다.

## 5. SAST 규칙별 변경

### WHSEC-001: 검증 호출 이름과 실제 제한 구분

이전에는 `hmac.new()` 또는 verify 계열 호출 이름이 보이면 서명 검증이 있다고 간주할 수 있었다.
보완 후에는 지원하는 비교/검증 결과가 거부 분기 또는 성공·실패 반환 구조에 사용되는지 확인한다.

```python
# 보완 전에는 놓칠 수 있던 예: 계산 결과를 사용하지 않는다.
unused = hmac.new(secret, payload, hashlib.sha256).hexdigest()
return {"processed": True}
```

이 경우 WHSEC-001 위험 징후를 보고한다.
추적할 수 없는 사용자 검증 함수는 이름만 믿지 않고 INFO로 표시한다. INFO만 있다고 전체 A로 처리하지 않는다.
일부 알려진 SDK 검증 호출은 명시한 목록으로 인식하지만, 모든 SDK나 모든 사용 방식을 지원하지 않는다.

### WHSEC-002: 일반 비교와 수정 예제

`==`, `!=`를 모두 점검하되, `signature == None`과 빈 헤더 존재 확인을 같은 취약 비교로 세지 않는다.
수정 예제는 원래 조건의 부정 의미를 유지한다.

```python
# 기존 코드
if signature != expected:
    raise ValueError("reject")

# 제공하는 참고 예제
if not hmac.compare_digest(signature, expected):
    raise ValueError("reject")
```

일반 비교를 찾았다는 사실이 원격 타이밍 공격 성공이나 시크릿 복구를 입증하지는 않는다.

### WHSEC-003: 알고리즘 전달 방식과 위험 설명

다음 표현을 모두 점검한다.

```python
hmac.new(secret, payload, hashlib.md5)
hmac.new(secret, payload, digestmod=hashlib.md5)
hmac.new(secret, payload, digestmod="md5")
# import hmac as hm / from hashlib import md5 as weak 형태도 포함
```

HMAC-MD5는 신규 설계에서 비권장이라는 점을 경고한다. MD5 충돌 실증만으로 HMAC 서명을 쉽게 위조할 수 있다고 단정하지 않는다.
MD5의 무조건 CRITICAL 9.1 처리를 MEDIUM 6.5의 규칙 참고값으로 조정했다.
SHA-1도 제공자 호환성과 허용 알고리즘 정책을 확인하도록 안내한다.
수정 예제에서 제공자와 무관하게 `sha256=` 접두사를 일방적으로 붙이던 부분을 줄였다.

### WHSEC-004: 시간 조회와 만료 검사 구분

현재 시간을 출력하는 코드만으로 검사 완료로 간주하지 않는다.
수신 시간과 현재 시간의 비교가 지원하는 처리 분기에 사용되는지 확인한다.
Toss의 전송 시각 헤더, PortOne의 `webhook-timestamp`도 시간 메타데이터로 인식한다.
수정 예제에는 시간값 자체도 제공자 명세에 따라 서명으로 보호되어야 한다는 조건을 추가했다.

현재 정적 규칙이 시간값의 모든 암호학적 연결을 추적하는 것은 아니다. 이 부분은 DAST 시간 헤더 갱신 시험과 수동 검토를 함께 사용한다.

### WHSEC-005: 외부 위치와 원래 핸들러 위치 분리

- `filepath`: 실제 결함이 있는 외부 파일 위치.
- `origin_filepath`: 그 외부 함수를 호출한 원래 핸들러 파일 위치.
- `related_rule_ids`: 외부에서 발견한 비교/해시 결함의 실제 항목(002 또는 003).

`group_findings()`는 `(origin_filepath 또는 filepath, handler_name)`으로 결과를 연결한다.
따라서 외부 파일 결함이 SAST-only 웹 응답에서 빠지거나 같은 함수명 때문에 다른 파일에 붙는 문제를 줄였다.
외부 파일 소스를 찾지 못하면 취약 확정 대신 INFO를 보고한다.

## 6. DAST 결과 상태와 기준선

### 유지한 인터페이스

`probe()`, `attack_downgrade()`, `attack_replay()`, `attack_type_confusion()`, `run_all()` 이름과 역할은 유지한다.
`AttackType`도 기존 3개를 유지한다.

### 추가한 결과 상태

| `status` | `vulnerable` | 의미 |
|---|---:|---|
| `vulnerable` | true | 시험 정책 위반 요청과 그 시험 주문의 상태 변경을 함께 확인 |
| `rejected` | false | 정상 기준 요청 성공 후 해당 시험 요청의 거부를 관측 |
| `observed` | false | 수락 또는 처리 관측은 있으나 취약 확정 조건 부족 |
| `inconclusive` | false | 기준 요청 실패·오류·비정상 응답 등으로 판단 불가 |
| `skipped` | false | 키 미입력, 프로토콜에 해당 시험을 적용할 수 없음 |

**`vulnerable=false`만 보고 안전이라고 해석하면 안 된다. 새 `status`를 함께 읽어야 한다.**
기존 JSON 소비자에서 boolean만 사용했다면 이 변경을 반영해야 한다.

### 정상 요청 기준선

Probe의 정상 서명 요청이 2xx이어야 동적 시험 결과를 해석한다.
잘못된 키, 이벤트 스키마 불일치, 잘못된 URL 등은 기준 요청 실패로 나타나며 안전으로 처리하지 않는다.
`requests.Response`의 truthiness 때문에 401·500 응답이 사라지던 부분을 `is not None`으로 구분했다.

302 리다이렉트를 자동으로 따라가지 않는다. 로그인 화면의 최종 200을 수신 성공으로 오인하지 않도록 했다.
500·429·404·연결 오류 등은 정상 방어 증거로 세지 않는다.

## 7. DAST 시나리오별 변경

### 다운그레이드/서명 정책

일반 HMAC·GitHub에는 약한 서명 및 서명 누락을 시험한다.
알고리즘 전환 문법이 없는 플랫폼에는 같은 공격군에서 잘못된 서명·서명 누락을 점검한다.
각 요청은 별도의 시험 주문과 연결하며, 2xx만으로 처리 성공을 확정하지 않는다.

SHA1 레거시 헤더 수락은 제공자 정책에 따라 허용될 수 있어 관측으로 분리한다.
HMAC을 깨서 서명을 위조했다고 설명하지 않는다.

### 재전송

고정된 6분 전 대신 `대상 허용 시간 + 60초` 이전 값을 사용한다. 기본 허용 시간은 기존과 같은 300초이다.

- 만료 시간값 + 그 시간값에 맞는 유효 서명.
- 적용 가능한 플랫폼에는 본문·서명을 유지한 채 시간 헤더만 현재 시각으로 바꾼 요청.

두 번째 요청은 시간 헤더가 서명에 결합되지 않은 결함을 드러내기 위한 기존 재전송 공격군의 하위 시험이다.
Stripe는 시간값이 서명 헤더 안에 있으므로 별도 헤더 갱신 하위 시험을 적용하지 않는다.
GitHub은 같은 시간 서명 형식이 없으므로 만료 시간 시험을 생략한다. 전달 ID 중복 처리/허용 창 안의 중복 이벤트 실행까지 검증한 것은 아니다.

### 타입 혼동/입력 정책

기존 `text/plain`과 배열 래핑을 유지한다.
기본적으로 유효 서명 입력의 형식 수락을 `observed`로 보고한다.
대상이 JSON 객체 전용이라는 계약이 있는 경우에만 `strict_json`을 켠다.
그 경우에도 상태 변경 증거가 있어야 정책 위반 처리로 집계한다.

배열·다른 Content-Type을 지원하도록 설계한 서버의 정상 동작을 무조건 취약점으로 만들지 않는다.

## 8. 상태 조회와 증거의 범위

이전에는 존재하지 않는 주문 ID로 시험하거나 `None != 상태값`을 변경 증거로 해석할 수 있었다.
지금은 가능한 경우 각 시험 전에 주문을 생성하고 실제 반환된 ID로 전후 상태를 조회한다.

- 생성 응답은 200뿐 아니라 201 등 2xx를 허용한다.
- 조회 응답은 `status` / `state`의 명확한 스칼라값만 읽는다. 응답의 첫 값(ID 등)을 임의로 상태로 사용하지 않는다.
- 이전 또는 이후 조회 실패는 상태 변경으로 인정하지 않는다.
- 고유 ID를 사용해 초 단위 ID 충돌을 줄였다.
- 비동기 대기 후에도 변화가 없으면 미확정으로 남긴다.

이 방식은 도구와 테스트 서버 사이의 관측 계약이다. 임의 서비스의 모든 업무 상태를 자동으로 이해하거나 DB를 직접 검증하는 것은 아니다.
시연 데이터의 보조 `order_id` 필드 등을 실제 수신 서버가 알아야 한다.

## 9. 플랫폼별 정정

### GitHub / Stripe / Slack

각자의 본문·시간 서명 형식을 분리한다.
Slack Probe에도 `X-Slack-Request-Timestamp`가 포함되도록 정상 헤더 생성 경로를 통일했다.
핸들러마다 플랫폼을 감지하므로 같은 파일의 Stripe·Slack 경로에 서로 다른 설정을 적용한다.

### 토스페이먼츠

보완 전 `HMAC(secret, body)`를 Base64로만 인코딩하던 코드를 수정했다.
서명이 제공되는 지급대행·셀러 이벤트에 맞춰 `body:transmission-time`을 서명하고 `v1:<Base64>` 형식을 생성한다.
전송 시각·전달 ID 헤더를 생성한다. 모의 이벤트는 `payout.changed`이다.

일반 결제 `PAYMENT_STATUS_CHANGED`에 이 서명이 있다고 가정하지 않는다.
결제 조회 API로 진위를 확인하는 일반 결제 연동 검증은 이번 자동 분석 범위 밖이다.
이 때문에 주 쇼핑몰 예제는 **사용자 정의 HMAC 모의 서비스**로 설명을 바로잡았다.
기존 데모 실행 키 문자열은 호환을 위해 유지했지만 실제 토스 키로 설명하지 않는다.

### PortOne V2

Standard Webhooks 형식에 맞춰 다음을 생성한다.

```text
서명 입력 = webhook-id + "." + webhook-timestamp + "." + raw body
키 = whsec_ 접두사를 제외한 Base64 시크릿을 디코딩한 바이트
헤더 = webhook-id / webhook-timestamp / webhook-signature: v1,<Base64>
```

잘못된 키 인코딩은 설정 오류로 보고한다. 모든 엔드포인트에 같은 키를 쓸 수 있다는 뜻은 아니다.
현재 UI 입력은 실행당 시크릿 하나이므로 서로 다른 실제 키를 사용하는 플랫폼은 따로 분석해야 한다.

위 변경은 서명 생성 형식과 모의 시험을 보완한 것이다. 실제 사업자 계정·실제 결제·모든 이벤트 스키마를 검증한 연동 인증은 아니다.

## 10. 등급·점수·교차 확인

`compute_endpoint_report()`는 DAST 단독 처리 증거도 위험 등급에 반영한다.
SAST INFO 안내는 취약점 건수에서 제외하지만, 미확인 범위가 있으므로 무조건 A를 주지는 않는다.

정적·동적 결과의 `related_rule_ids`가 같은 경우에만 같은 항목의 증거가 있다고 표시한다.
예를 들어 SAST 일반 비교(002)와 DAST 재전송(004)을 같은 취약점의 재현으로 표시하지 않는다.

기존 CVSS +0.5 가산을 없앴다.
JSON 호환을 위해 `cvss_score`, `overall_cvss`라는 필드명은 유지했지만, 화면·문서에는 **규칙 참고 위험도**로 표시한다.
환경별 영향과 공격 조건을 평가한 CVSS 벡터/공식 점수를 새로 계산한 것은 아니다.

A는 지원 범위 안에서 위험 징후가 없다는 의미이다.
오류·미추적·수락 관측·생략만 있는 경우에는 N/A와 partial 상태를 사용한다.
이미 위험이 탐지된 경우에는 위험 등급과 partial 상태를 함께 제공한다.

## 11. 웹 API·CLI·화면 변경

### API

- 기존 `POST /analyze` 입력과 응답 키를 유지하고 결과 상태 등의 키를 추가했다.
- `strict_json`(기본 false), `timestamp_tolerance`(기본 300)를 추가했다.
- 정상 요청 기준 결과를 엔드포인트별 `probe`로 응답한다.
- 원래 핸들러 파일 정보를 사용해 외부 Finding을 연결한다.
- 일부 파일이 파싱되지 않으면 누락 사실을 `analysis_warnings`에 표시한다.
- 중복 경로·미치환 경로 변수·POST 외 메서드는 추측해 호출하지 않고 판단 불가로 남긴다.
- 업로드 읽기 크기를 제한하고, 생성한 세션·임시 파일은 정리한다.

### CLI

기존 옵션에 아래 둘을 추가했다.

```bash
--strict-json
--timestamp-tolerance 300
```

0은 점검 범위 내 미탐지, 1은 위험 징후/처리 증거 탐지, 2는 입력 오류·분석 미완료이다.
외부 함수를 포함한 그룹핑과 플랫폼별 DAST 설정을 웹 경로와 맞췄다.

### 화면

- 판단 불가·생략·수락 관측을 초록색 안전 카드로 표시하지 않는다.
- N/A는 별도 스타일로 표시한다.
- 동적 처리 증거·수락 관측·판단 불가·생략 수를 구분한다.
- 정상 서명 기준 요청이 성공했는지 보여 준다.
- 엔드포인트별 플랫폼과 참고 문서를 사용한다.
- URL을 비우는 SAST-only 동작을 UI에서도 사용할 수 있다.
- 시크릿 입력을 password 타입으로 바꿨다.

## 12. 샘플·업로드 처리 변경의 이유

안전 예제는 서명되지 않은 시간 헤더만 검사하던 구조를 보완해 서명된 본문 시간값을 검사한다.
이전의 본문·서명 유지 + 시간 헤더 갱신 반례가 거부되는 것을 시험했다.
일반 HMAC 예제는 GitHub 고유 헤더 대신 X-Signature로 구분한다.

다운그레이드 예제는 정상 SHA256 요청도 받으면서 약한 방식도 받는 결함으로 표현했다.
정상 SHA256 자체를 지원하지 않는 서버는 정상 요청 기준선 실패로 보고해야 하기 때문이다.

ZIP 업로드는 기존 `..` 검사에 더해 절대 경로·Windows 경로·링크·해제 경계·항목 수를 확인한다.
기존 업로드 10MiB, 누적 해제 50MiB 제한은 유지한다.

## 13. 검증 결과와 실행 환경

| 확인 항목 | 결과 |
|---|---|
| 단위·회귀 테스트 | **55개 통과, 실패 0, 오류 0** |
| 기존 통합 테스트 | **22개 검사 통과, 종료 코드 0** |
| 통합 테스트 SAST | 예제 위험 징후 7건 |
| 통합 테스트 DAST | 핵심 6개 예제 경로에서 처리 증거 결과 15건 |
| JavaScript | 문법·실제 렌더링 함수·미확정 표시·HTML escaping 검사 통과 |
| Python 3.10 구문 | 모든 Python 파일 AST 구문 검사 통과 |

15건은 하위 시험 결과 건수이며 독립적인 취약점 15종을 뜻하지 않는다.
동적 숫자는 새로운 분류 기준을 적용한 결과이다. 포스터의 16건과 맞추기 위해 조건을 조작하지 않았다.

실행 환경은 Python 3.12.14이다.
이 환경에 프로젝트 의존성이 설치되지 않았고 네트워크 설치가 되지 않아, HTTP 엔진 시험에는 환경에 포함된 `requests 2.34.2`를 사용했다.
프로젝트 `requirements.txt`의 버전 고정은 변경하지 않았다.

`test_api_pipeline.py`는 실제 analyze 함수를 실행하지만, 이 환경에서는 FastAPI 선언 인터페이스를 대역으로 제공했다.
따라서 **실제 FastAPI/Starlette ASGI 라우팅·multipart 수신·Uvicorn 실행을 통과했다고 주장하지 않는다.**
Playwright 패키지는 있으나 브라우저 실행 파일이 없어 실제 브라우저 시각 검증도 하지 못했다.
대신 실제 프런트엔드 JavaScript 렌더링 함수를 Node에서 실행해 상태 표시와 escaping을 확인했다.
Python 3.10 실제 런타임과 공식 사업자 서버에서의 상호운용성도 이번 환경에서는 검증하지 않았다.

검증 기록은 `docs/verification/`에 포함했다.

## 14. 로컬 재현 순서

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
python tests/test_integration.py
uvicorn samples.shop_server:app --port 8000
# 다른 터미널
uvicorn app:app --port 8001
```

웹 화면에 `samples/shop_server.py`, `http://127.0.0.1:8000`,
`dku-toss-secret-2026`, `/orders`, `/orders/{id}`를 입력한다.
기본적으로 strict_json은 선택하지 않는다. 이 예제는 실제 결제 제공자 연동이 아니다.

추가로 확인할 수동 항목:

1. `.py`와 외부 함수를 포함한 `.zip` 모두에서 결과 파일·줄 위치가 맞는지 확인.
2. 키를 틀리게 입력하면 정상 요청 기준 실패와 판단 불가가 표시되는지 확인.
3. URL을 비우면 정적분석만 실행되는지 확인.
4. 생성·조회 경로를 비우면 Tier 2의 수락 관측과 취약 확정이 구분되는지 확인.
5. 실제 서비스별 이벤트 스키마·시크릿·경로·허용 시간을 해당 제공자 명세에 맞춰 입력.

## 15. 남아 있는 한계와 후속 범위

이번 보완으로 도구가 모든 Python 수신 코드를 완전하게 판정하게 된 것은 아니다.
다음은 한계 또는 별도 후속 작업이다.

- 모든 실행 경로·데이터 흐름·예외 흐름의 완전한 정적 검증.
- 사용자 정의 인증, 미들웨어, 모든 SDK·의존성 주입 지원.
- 라우터 prefix/Blueprint 등록 관계 자동 합성.
- 서비스별 실제 업무 데이터·인증이 있는 상태 조회 API 자동 적응.
- 허용 시간 안의 정확히 같은 이벤트 재처리, 카운터·로그 등 모든 중복 효과 검증.
- 환경별 CVSS 벡터와 실제 영향에 근거한 점수 산출.
- 공식 SDK 및 실제 제공자 테스트 이벤트를 이용한 상호운용성 시험.
- 인증·다중 사용자 작업 큐·대규모 소스 격리. 현재 analyze 함수 내부의 동기 분석/HTTP 작업도 작업 큐로 분리하지 않았다.

이 한계를 INFO·판단 불가·지원 범위 내 미탐지라는 표현으로 드러내는 것이 이번 판정 보완의 일부이다.

## 16. 확인한 공식 자료

2026-10-20 확인. 아래 문서는 형식·해석의 근거이며, 전체 규칙 정확도를 인증하는 자료는 아니다.

- [GitHub 서명 검증](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries): raw body HMAC, SHA256 형식.
- [GitHub 웹훅 권장 사항](https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks): 전달 ID와 중복 처리.
- [Stripe 웹훅](https://docs.stripe.com/webhooks): 시간값 서명, 허용 시간과 재전송, raw body.
- [Slack 요청 검증](https://docs.slack.dev/authentication/verifying-requests-from-slack/): `v0:timestamp:body` 서명.
- [토스 웹훅 이벤트](https://docs.tosspayments.com/reference/using-api/webhook-events): 서명 제공 이벤트, 본문·전송 시각과 v1/Base64 형식.
- [PortOne 웹훅](https://developers.portone.io/opi/ko/integration/webhook/readme-v2): Standard Webhooks 적용.
- [Standard Webhooks 명세](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md): ID·시간·본문 서명과 헤더.
- [RFC 6151](https://www.rfc-editor.org/rfc/rfc6151): MD5와 HMAC-MD5의 보안 영향 구분.
- [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document): 정의된 평가 항목과 벡터에 근거한 점수.
