"""
analyzer/dast.py

동적 분석(DAST) — Probe + 3가지 공격 통합

Probe 4단계로 Tier를 자동 분류한 뒤 3종의 공격을 수행한다.

공격 종류:
  1) 다운그레이드: sha256 → sha1 → md5 → 서명 없음 순으로 시도
  2) 재전송: 만료 타임스탬프 + 유효 서명
  3) 타입 혼동: Content-Type 변조(Stage A), 배열 래핑(Stage B)

Tier별 동작 차이:
  Tier 1 (상태 조회 가능):
    공격 전후 상태 DB를 비교해 높은 신뢰도로 판정한다.
    HTTP 수락과 실제 상태 변경을 구분하며, 판정 불가/생략을 별도로 반환한다.
  Tier 2 (상태 조회 불가):
    HTTP 2xx 수락 여부만 관측한다.
    HTTP 수락은 OBSERVED로 반환하며 취약 확정으로 집계하지 않는다.
    SAST 결과와 함께 추가 확인한다.

지원 플랫폼: GitHub, Stripe, 토스페이먼츠, Slack, PortOne V2
  각 플랫폼의 서명 형식과 페이로드 구조에 맞춰 공격 요청을 조립한다.
"""
import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict

import requests


# 데이터 구조
class Tier(Enum):
    TIER_1 = "Tier 1"
    TIER_2 = "Tier 2"


class AttackType(Enum):
    DOWNGRADE      = "downgrade"
    REPLAY         = "replay"
    TYPE_CONFUSION = "type_confusion"


class Verdict(Enum):
    VULNERABLE = "vulnerable"
    REJECTED = "rejected"
    OBSERVED = "observed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class Confidence(Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class ProbeResult:
    endpoint: str
    tier: Tier = Tier.TIER_2
    step1_code: int = 0
    step1_accepted: bool = False
    step2_code: int = 0
    step3_code: int = 0
    step3_body: str = ""
    step4_state_ok: bool = False
    connection_error: str = ""
    details: List[str] = field(default_factory=list)
    baseline_valid: bool = False
    invalid_signature_rejected: bool = False
    validation_error: str = ""


@dataclass
class AttackResult:
    attack_type: AttackType
    endpoint: str
    tier: Tier
    vulnerable: bool
    confidence: Confidence
    description: str
    details: List[str] = field(default_factory=list)
    status_code: int = 0
    state_changed: bool = False
    status: Verdict = None
    variant: str = ""
    related_rule_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.status is None:
            self.status = Verdict.VULNERABLE if self.vulnerable else Verdict.REJECTED
        self.vulnerable = self.status == Verdict.VULNERABLE


@dataclass
class DastConfig:
    base_url: str
    secret: bytes = b""
    timeout: float = 10.0
    state_create_path: str = "/orders"
    state_query_template: str = "/orders/{id}"
    sig_header: str = "X-Hub-Signature-256"
    is_stripe: bool = False
    is_slack: bool = False
    platform_name: str = "generic"
    request_interval: float = 0.3   # 공격 요청 사이 대기 시간(초) — Rate Limit 방지
    max_retries: int = 1
    timestamp_tolerance: int = 300
    strict_json: bool = False  # 사용자가 JSON 객체 전용 정책을 명시한 경우에만 적용
    state_check_delay: float = 2.0  # 공격 후 상태 조회 전 대기(초) — 비동기 워커 처리 대기


# 플랫폼별 Mock 페이로드 생성기
def _generate_mock_payload(platform_name: str, order_id: str,
                           timestamp: int = None) -> bytes:
    """
    플랫폼별 실제 이벤트 형식에 맞는 테스트용 페이로드를 생성한다.

    빈 JSON {}을 보내면 서버가 파라미터 오류(400)를 반환할 수 있어
    서명 검증 실패(401)와 구별이 안 된다. 실제 형식으로 보내야
    서버가 서명 검증 단계까지 진행한다.

    timestamp: 재전송 공격 시 헤더와 본문의 타임스탬프를 일치시키기 위해 사용한다.
      None이면 현재 시간을 사용하고, int 값이면 해당 타임스탬프를 모든 시간 필드에 적용한다.
      서버가 헤더 대신 본문의 타임스탬프 필드로 만료를 검증할 때도 정확히 동작하도록 보장한다.
    """
    ts = timestamp if timestamp is not None else int(time.time())
    ts_iso = datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")

    if platform_name in ("github", "GitHub"):
        payload = {
            "ref": "refs/heads/main",
            "before": "0" * 40,
            "after": "a" * 40,
            "repository": {
                "id": 12345,
                "full_name": "analyzer/test-repo",
                "private": False,
            },
            "sender": {"login": "webhook-analyzer"},
            "commits": [],
            "order_id": order_id,
            "status": "paid",
        }

    elif platform_name in ("stripe", "Stripe"):
        payload = {
            "id": f"evt_analyzer_{order_id}",
            "object": "event",
            "type": "payment_intent.succeeded",
            "created": ts,
            "livemode": False,
            "data": {
                "object": {
                    "id": f"pi_{order_id}",
                    "amount": 10000,
                    "currency": "krw",
                    "status": "succeeded",
                }
            },
            "order_id": order_id,
            "status": "paid",
        }

    elif platform_name in ("토스페이먼츠", "toss", "toss_payments", "TOSS_PAYMENTS"):
        payload = {
            "eventType": "payout.changed",
            "eventId": f"evt_{order_id}",
            "entityType": "payout",
            "entityBody": {"id": f"payout_{order_id}", "status": "COMPLETED"},
            "createdAt": ts_iso,
            "data": {
                "paymentKey": f"paykey_{order_id}",
                "orderId": order_id,
                "status": "DONE",
                "totalAmount": 10000,
                "method": "카드",
                "requestedAt": ts_iso,
                "approvedAt": ts_iso,
            },
            "order_id": order_id,
            "status": "paid",
        }

    elif platform_name in ("slack", "Slack"):
        payload = {
            "token": "analyzer_token",
            "team_id": "T0001ANALYZER",
            "api_app_id": "A0001ANALYZER",
            "event": {
                "type": "message",
                "text": "webhook-analyzer test",
                "user": "U0001ANALYZER",
                "ts": str(ts),
            },
            "type": "event_callback",
            "event_id": f"Ev{order_id}",
            "event_time": ts,
            "order_id": order_id,
            "status": "paid",
        }

    elif platform_name in ("portone", "portone_v2", "PortOne V2"):
        payload = {
            "type": "Transaction.Paid",
            "timestamp": ts_iso,
            "data": {
                "transactionId": f"tx_{order_id}",
                "paymentId": f"pay_{order_id}",
                "storeId": "store_analyzer",
                "status": "PAID",
                "amount": {"total": 10000, "currency": "KRW"},
            },
            "order_id": order_id,
            "status": "paid",
        }

    else:
        payload = {
            "order_id": order_id,
            "status": "paid",
            "event": "test.created",
            "timestamp": ts,
        }

    return json.dumps(payload, ensure_ascii=False).encode()


# DAST 엔진
class DASTEngine:
    REJECTION_CODES = {400, 401, 403, 415, 422}

    def __init__(self, config: DastConfig):
        self.cfg = config
        self.s = requests.Session()
        self.s.trust_env = False

    def close(self):
        self.s.close()

    @property
    def platform(self):
        name = self.cfg.platform_name.lower()
        if self.cfg.is_stripe or name == 'stripe':
            return 'stripe'
        if self.cfg.is_slack or name == 'slack':
            return 'slack'
        if name in {'toss', 'toss_payments', '토스페이먼츠'}:
            return 'toss'
        if name in {'portone', 'portone_v2', 'portone v2'}:
            return 'portone'
        return 'github' if name == 'github' else 'generic'

    def _result(self, kind, path, probe, status, description, *, code=0,
                details=None, changed=False, variant='', related=None):
        return AttackResult(kind, path, probe.tier, status == Verdict.VULNERABLE,
                            Confidence.HIGH if changed else (Confidence.MEDIUM if status == Verdict.REJECTED else Confidence.LOW),
                            description, details or [], code, changed, status,
                            variant, related or [])

    def _ready(self, kind, path, probe):
        if not self.cfg.secret:
            return self._result(kind, path, probe, Verdict.SKIPPED,
                                '시크릿 미입력 — 정상 서명 기준 요청을 만들 수 없어 시험 생략')
        if not probe.baseline_valid:
            return self._result(kind, path, probe, Verdict.INCONCLUSIVE,
                                '정상 서명 기준 요청 실패 — 취약 여부 판단 불가',
                                details=[probe.validation_error or f'기준 응답: {probe.step3_code}'])
        return None

    def probe(self, path: str, sig_header: str = None) -> ProbeResult:
        sig_header = sig_header or self.cfg.sig_header
        result = ProbeResult(endpoint=path)
        payload = _generate_mock_payload(self.platform, 'probe_' + uuid.uuid4().hex)
        ts = str(int(time.time()))
        try:
            good = self._build_sig_headers(sig_header, payload, ts)
            bad = self._build_sig_headers(sig_header, payload, ts, secret=b'wrong-key-for-test')
        except (ValueError, TypeError) as exc:
            result.validation_error = f'서명 설정 오류: {type(exc).__name__}'
            result.details.append(result.validation_error)
            return result
        missing = {k: v for k, v in good.items() if k.lower() != sig_header.lower()}
        for step, headers in [(1, missing), (2, bad), (3, good)]:
            if step == 3 and not self.cfg.secret:
                result.details.append('Step3 생략: 시크릿 미입력')
                continue
            resp, error = self._post_safe(self.cfg.base_url + path, payload, headers)
            code = resp.status_code if resp is not None else 0
            setattr(result, f'step{step}_code', code)
            result.details.append(f'Step{step} → {code}' + (f' ({error})' if error else ''))
            if error:
                result.connection_error = error
            if step == 1:
                result.step1_accepted = 200 <= code < 300
            if step == 2:
                result.invalid_signature_rejected = code in self.REJECTION_CODES
            if step == 3:
                result.baseline_valid = 200 <= code < 300
                if not result.baseline_valid:
                    result.validation_error = '정상 요청 실패: 키·플랫폼·이벤트·경로·서버 상태 확인 필요'
        result.step4_state_ok = self._check_state_endpoint()
        result.tier = Tier.TIER_1 if result.step4_state_ok else Tier.TIER_2
        result.details.append(f'Step4 상태 조회: {result.step4_state_ok} → {result.tier.value}')
        return result

    def _case(self, probe, timestamp=None):
        order_id = self._create_order() if probe.tier == Tier.TIER_1 else None
        if order_id is None:
            order_id = 'case_' + uuid.uuid4().hex
        before = self._query_state(order_id) if probe.tier == Tier.TIER_1 else None
        return _generate_mock_payload(self.platform, order_id, timestamp), order_id, before

    def _changed(self, probe, order_id, before):
        if probe.tier != Tier.TIER_1 or before is None:
            return False
        time.sleep(max(0.0, self.cfg.state_check_delay))
        after = self._query_state(order_id)
        # 조회 실패(None)는 상태 변경 증거가 아니다.
        return after is not None and before != after

    def _evaluate(self, kind, path, probe, payload, headers, order_id, before,
                  description, variant, related=None, policy_applies=True):
        response, error = self._post_safe(self.cfg.base_url + path, payload, headers)
        code = response.status_code if response is not None else 0
        details = [f'HTTP {code}']
        if error or code not in self.REJECTION_CODES and not 200 <= code < 300:
            return self._result(kind, path, probe, Verdict.INCONCLUSIVE,
                                description + ' — 오류/비정상 응답으로 판단 불가', code=code,
                                details=details + ([error] if error else []), variant=variant)
        if code in self.REJECTION_CODES:
            return self._result(kind, path, probe, Verdict.REJECTED,
                                description + ' — 시험 요청 거부 관측', code=code,
                                details=details, variant=variant)
        changed = self._changed(probe, order_id, before)
        status = Verdict.VULNERABLE if changed and policy_applies else Verdict.OBSERVED
        details.append('시험 주문 상태 변경 확인' if changed else '처리 효과 미확인 — HTTP 수락만 관측')
        if not policy_applies:
            details.append('수락 자체로 보안 취약점을 확정하지 않음')
        return self._result(kind, path, probe, status, description +
                            (' — 정책 위반 처리 증거 확인' if status == Verdict.VULNERABLE else ' — 수락 관측, 추가 검토 필요'),
                            code=code, details=details, changed=changed,
                            variant=variant, related=related)

    def attack_downgrade(self, path, probe, sig_header=None):
        if (unready := self._ready(AttackType.DOWNGRADE, path, probe)):
            return [unready]
        sig_header = sig_header or self.cfg.sig_header
        # 알고리즘 선택 문법이 없는 플랫폼은 누락/잘못된 서명을 같은 공격군에서 점검한다.
        variants = ['sha1', 'md5'] if self.platform in {'github', 'generic'} else ['invalid_signature']
        if self.platform == 'github' or 'hub' in sig_header.lower():
            variants.append('sha1_legacy')
        variants.append('missing_signature')
        results = []
        for variant in variants:
            payload, order_id, before = self._case(probe)
            headers = self._build_sig_headers(sig_header, payload, str(int(time.time())))
            if variant == 'missing_signature':
                headers.pop(sig_header, None)
            elif variant == 'invalid_signature':
                headers[sig_header] = 'invalid-signature-for-test'
            else:
                algo = 'sha1' if variant == 'sha1_legacy' else variant
                value = algo + '=' + hmac.new(self.cfg.secret, payload, algo).hexdigest()
                if variant == 'sha1_legacy':
                    headers.pop(sig_header, None)
                    headers['X-Hub-Signature'] = value
                else:
                    headers[sig_header] = value
            related = ['WHSEC-001'] if variant in {'missing_signature', 'invalid_signature'} or not probe.invalid_signature_rejected else ['WHSEC-003']
            results.append(self._evaluate(AttackType.DOWNGRADE, path, probe, payload, headers,
                           order_id, before, f'서명 정책 시험({variant})', variant, related,
                           policy_applies=variant != 'sha1_legacy'))
        return results

    def attack_replay(self, path, probe, sig_header=None):
        if (unready := self._ready(AttackType.REPLAY, path, probe)):
            return [unready]
        if self.platform == 'github':
            return [self._result(AttackType.REPLAY, path, probe, Verdict.SKIPPED,
                    'GitHub은 서명된 시간값을 제공하지 않음 — 이 만료 시간 시험은 적용 불가; 전달 ID 중복 처리는 별도 검토')]
        sig_header = sig_header or self.cfg.sig_header
        expired = int(time.time()) - max(1, self.cfg.timestamp_tolerance) - 60
        results = []
        variants = ['expired_timestamp', 'timestamp_header_refresh'] if self.platform in {'generic', 'slack', 'toss', 'portone'} else ['expired_timestamp']
        for variant in variants:
            payload, order_id, before = self._case(probe, expired)
            headers = self._build_sig_headers(sig_header, payload, str(expired))
            if variant == 'timestamp_header_refresh':
                key = {'slack': 'X-Slack-Request-Timestamp', 'toss': 'TossPayments-Webhook-Transmission-Time',
                       'portone': 'webhook-timestamp', 'generic': 'X-Timestamp'}[self.platform]
                now = str(int(time.time()))
                headers[key] = self._toss_time(now) if self.platform == 'toss' else now
            results.append(self._evaluate(AttackType.REPLAY, path, probe, payload, headers,
                           order_id, before, '만료 요청 시험' if variant == 'expired_timestamp' else '본문·서명 유지 후 시간 헤더만 갱신',
                           variant, ['WHSEC-004']))
        return results

    def attack_type_confusion(self, path, probe, sig_header=None):
        if (unready := self._ready(AttackType.TYPE_CONFUSION, path, probe)):
            return [unready]
        sig_header = sig_header or self.cfg.sig_header
        results = []
        for variant in ['text_plain', 'array_body']:
            payload, order_id, before = self._case(probe)
            if variant == 'array_body':
                payload = json.dumps([json.loads(payload)], ensure_ascii=False).encode()
            headers = self._build_sig_headers(sig_header, payload, str(int(time.time())))
            if variant == 'text_plain':
                headers['Content-Type'] = 'text/plain'
            result = self._evaluate(AttackType.TYPE_CONFUSION, path, probe, payload, headers,
                       order_id, before, f'입력 형식 시험({variant})', variant,
                       policy_applies=self.cfg.strict_json)
            result.details.append('유효 서명으로 입력 정책을 시험함 — 인증 우회 시험이 아님')
            results.append(result)
        return results

    def run_all(self, path, probe, sig_header=None):
        return (self.attack_downgrade(path, probe, sig_header) +
                self.attack_replay(path, probe, sig_header) +
                self.attack_type_confusion(path, probe, sig_header))

    @staticmethod
    def _toss_time(ts):
        return datetime.fromtimestamp(int(ts), timezone.utc).isoformat(timespec='seconds') if str(ts).isdigit() else str(ts)

    @staticmethod
    def _message_id(payload):
        try:
            value = json.loads(payload)
            if isinstance(value, list):
                value = value[0]
            return str(value.get('eventId') or value.get('id') or value.get('order_id') or 'msg_analyzer')
        except (ValueError, IndexError, AttributeError, TypeError):
            return 'msg_analyzer'

    def _make_signature(self, secret, payload, timestamp=None, message_id=None):
        ts = timestamp or str(int(time.time()))
        if self.platform == 'stripe':
            value = hmac.new(secret, f'{ts}.'.encode() + payload, hashlib.sha256).hexdigest()
            return f't={ts},v1={value}'
        if self.platform == 'slack':
            return 'v0=' + hmac.new(secret, f'v0:{ts}:'.encode() + payload, hashlib.sha256).hexdigest()
        if self.platform == 'toss':
            signed = payload + b':' + self._toss_time(ts).encode()
            return 'v1:' + base64.b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).decode()
        if self.platform == 'portone':
            encoded = secret[6:] if secret.startswith(b'whsec_') else secret
            key = base64.b64decode(encoded, validate=True)
            if not key:
                raise ValueError('Empty PortOne secret')
            signed = f'{message_id or self._message_id(payload)}.{ts}.'.encode() + payload
            return 'v1,' + base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
        return 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()

    def _build_sig_headers(self, sig_header, payload, ts, secret=None):
        secret = self.cfg.secret if secret is None else secret
        if self.platform == 'portone' and secret == b'wrong-key-for-test':
            secret = base64.b64encode(secret)
        headers = {'Content-Type': 'application/json', sig_header: self._make_signature(secret, payload, ts)}
        if self.platform == 'slack':
            headers['X-Slack-Request-Timestamp'] = ts
        elif self.platform == 'toss':
            headers['TossPayments-Webhook-Transmission-Time'] = self._toss_time(ts)
            headers['TossPayments-Webhook-Transmission-Id'] = self._message_id(payload)
        elif self.platform == 'portone':
            headers.update({'webhook-id': self._message_id(payload), 'webhook-timestamp': ts})
        elif self.platform == 'github':
            headers.update({'X-GitHub-Event': 'push', 'X-GitHub-Delivery': self._message_id(payload)})
        elif self.platform != 'stripe':
            headers['X-Timestamp'] = ts
        return headers

    def _post_safe(self, url, payload, extra_headers):
        headers = {'Content-Type': 'application/json', **extra_headers}
        time.sleep(max(0.0, self.cfg.request_interval))
        for attempt in range(1 + max(0, self.cfg.max_retries)):
            try:
                return self.s.post(url, data=payload, headers=headers, timeout=self.cfg.timeout,
                                   allow_redirects=False), None
            except requests.exceptions.RequestException as exc:
                error = type(exc).__name__
        return None, error

    def _post_raw_safe(self, url, payload, headers):
        return self._post_safe(url, payload, headers)

    def _create_order(self):
        if not self.cfg.state_create_path or not self.cfg.state_query_template:
            return None
        try:
            response = self.s.post(self.cfg.base_url + self.cfg.state_create_path,
                        json={'item': 'analyzer_test'}, timeout=self.cfg.timeout, allow_redirects=False)
            if 200 <= response.status_code < 300:
                body = response.json()
                if isinstance(body, dict):
                    for key in ('order_id', 'id', 'pk'):
                        if body.get(key) is not None:
                            return str(body[key])
        except (requests.exceptions.RequestException, ValueError):
            pass
        return None

    def _check_state_endpoint(self):
        order_id = self._create_order()
        return order_id is not None and self._query_state(order_id) is not None

    def _query_state(self, order_id):
        if not self.cfg.state_query_template or '{id}' not in self.cfg.state_query_template:
            return None
        from urllib.parse import quote
        path = self.cfg.state_query_template.replace('{id}', quote(str(order_id), safe=''))
        try:
            response = self.s.get(self.cfg.base_url + path, timeout=self.cfg.timeout, allow_redirects=False)
            if response.status_code == 200:
                body = response.json()
                if isinstance(body, dict):
                    for key in ('status', 'state'):
                        value = body.get(key)
                        if value is not None and isinstance(value, (str, int, float, bool)):
                            return str(value)
        except (requests.exceptions.RequestException, ValueError):
            pass
        return None
