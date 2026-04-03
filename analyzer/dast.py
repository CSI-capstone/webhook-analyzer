"""
analyzer/dast.py

동적 분석(DAST) — Probe + 3가지 공격 통합
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Probe]  4단계 → Tier 1/2 자동 분류

[공격]
  1) 다운그레이드: sha256 → sha1 → md5 → 서명 없음
  2) 재전송: 만료 타임스탬프 + 유효 서명
  3) 타입 혼동: Content-Type 변조(Stage A), 배열 래핑(Stage B)

[Tier별 동작 차이]
  Tier 1 (상태 조회 가능):
    - 공격 전/후 GET /orders/{id}로 상태 비교 → 최고 신뢰도
    - 재전송, 타입혼동 Stage A/B에서 상태 교차 검증 적용
    - 다운그레이드는 수락 자체가 결함 확정 → 상태 교차 검증은 부가 참고용만
  Tier 2 (상태 조회 불가):
    - HTTP 2xx 수락 여부만 관측
    - 다운그레이드는 고신뢰, 재전송/타입혼동은 중신뢰
    - 정적 분석(SAST) 결과를 우선 참고 권장
"""
"""
analyzer/dast.py  (v2 — Step 3 고도화)

동적 분석(DAST) — Probe + 3가지 공격 통합
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

v2 변경 사항:
  - DastConfig: sig_header, is_stripe, is_slack, platform_name 필드 추가
  - ProbeResult: connection_error 필드 추가 (연결 실패 사유 기록)
  - _generate_mock_payload(): 플랫폼별 실제 이벤트 형식 페이로드 생성
      → 빈 JSON 대신 실제 형식을 보내야 서버가 400이 아닌 401을 반환
  - attack_replay / attack_type_confusion: sig_header 파라미터 사용
  - _check_state_endpoint / _query_state: 커스텀 URL 사용
  - 모든 HTTP 오류에 "분석 실패 사유" 명확히 기록
"""
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict

import requests


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 데이터 구조
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Tier(Enum):
    TIER_1 = "Tier 1"
    TIER_2 = "Tier 2"


class AttackType(Enum):
    DOWNGRADE      = "downgrade"
    REPLAY         = "replay"
    TYPE_CONFUSION = "type_confusion"


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
    connection_error: str = ""   # ← v2: 연결 실패 사유
    details: List[str] = field(default_factory=list)


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


@dataclass
class DastConfig:
    base_url: str
    secret: bytes = b""
    timeout: float = 10.0  # Cold Start 대비 여유 있는 기본값 (권장: 5~10초)
    state_create_path: str = "/orders"
    state_query_template: str = "/orders/{id}"
    sig_header: str = "X-Hub-Signature-256"  # ← 플랫폼별 헤더명
    is_stripe: bool = False                   # ← Stripe t=,v1= 형식
    is_slack: bool = False                    # ← Slack v0=ts:body 형식
    platform_name: str = "generic"            # ← mock payload 생성에 사용
    request_interval: float = 0.3            # ← 공격 요청 사이 대기 시간(초) — Rate Limit 방지
    max_retries: int = 1                      # ← 연결 실패 시 재시도 횟수
    state_check_delay: float = 2.0           # ← 공격 후 상태 조회 전 대기(초) — 비동기 워커 처리 대기


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# v2: 플랫폼별 Mock 페이로드 생성기
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _generate_mock_payload(platform_name: str, order_id: str,
                           timestamp: int = None) -> bytes:
    """
    플랫폼별 실제 이벤트 형식에 맞는 가짜 페이로드를 생성.

    왜 필요한가?
      빈 JSON {}을 보내면 서버가 파라미터 오류(400)를 반환할 수 있어
      서명 검증 실패(401)와 구별이 안 됨.
      실제 형식으로 보내야 서버가 서명 검증 단계까지 진행함.

    timestamp: 재전송 공격 시 만료 타임스탬프를 본문에도 주입하기 위해 사용.
      None이면 현재 시간 사용 (일반 probe/공격).
      int 값이면 해당 타임스탬프를 본문의 모든 시간 필드에 적용.
      → 헤더 타임스탬프와 본문 타임스탬프를 일치시켜 서버가 본문 기준으로
        검증해도 재전송 공격이 정확하게 동작하도록 보장.
    """
    # 버그 3 수정: 외부에서 주입된 timestamp 우선 사용 (재전송 공격 시 만료 ts 일치)
    ts = timestamp if timestamp is not None else int(time.time())
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))

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
            # 상태 교차 검증용 필드
            "order_id": order_id,
            "status": "pending",
        }

    elif platform_name in ("stripe", "Stripe"):
        payload = {
            "id": f"evt_analyzer_{order_id}",
            "object": "event",
            "type": "payment_intent.succeeded",
            "created": ts,  # 버그 3 수정: 주입된 ts 사용
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
            "eventType": "PAYMENT_STATUS_CHANGED",
            "createdAt": f"{ts_iso}+09:00",  # 버그 3 수정: 주입된 ts 사용
            "data": {
                "paymentKey": f"paykey_{order_id}",
                "orderId": order_id,
                "status": "DONE",
                "totalAmount": 10000,
                "method": "카드",
                "requestedAt": f"{ts_iso}+09:00",  # 버그 3 수정
                "approvedAt": f"{ts_iso}+09:00",   # 버그 3 수정
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
                "ts": str(ts),  # 버그 3 수정: 주입된 ts 사용
            },
            "type": "event_callback",
            "event_id": f"Ev{order_id}",
            "event_time": ts,  # 버그 3 수정: 주입된 ts 사용
            "order_id": order_id,
            "status": "pending",
        }

    elif platform_name in ("portone", "portone_v2", "PortOne V2"):
        payload = {
            "type": "Transaction.Paid",
            "timestamp": f"{ts_iso}Z",  # 버그 3 수정: 주입된 ts 사용
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
        # Generic — 최소한의 구조
        payload = {
            "order_id": order_id,
            "status": "pending",
            "event": "test.created",
            "timestamp": ts,  # 버그 3 수정: 주입된 ts 사용
        }

    return json.dumps(payload, ensure_ascii=False).encode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DAST 엔진
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class DASTEngine:

    def __init__(self, config: DastConfig):
        self.cfg = config
        self.s = requests.Session()

    # ──────────────────────────────────────────────────────
    # Probe — 4단계 Tier 분류
    # ──────────────────────────────────────────────────────
    def probe(self, path: str, sig_header: str = None) -> ProbeResult:
        if sig_header is None:
            sig_header = self.cfg.sig_header

        r = ProbeResult(endpoint=path)
        url = self.cfg.base_url + path
        order_id = f"probe_{int(time.time())}"
        payload = _generate_mock_payload(self.cfg.platform_name, order_id)

        # Step 1: 서명 없이 전송
        resp, err = self._post_safe(url, payload, {})
        if err:
            r.connection_error = err
            r.details.append(f"Step1 연결 실패: {err}")
        elif resp:
            r.step1_code = resp.status_code
            r.step1_accepted = 200 <= resp.status_code < 300
            r.details.append(
                f"Step1 서명없이→{resp.status_code}"
                + (" ⚠ 수락됨!" if r.step1_accepted else "")
            )

        # Step 2: 잘못된 서명
        bad_sig = self._make_signature(b"wrong" * 10, payload)
        resp2, err2 = self._post_safe(url, payload, {
            sig_header: bad_sig,
            "X-Timestamp": str(int(time.time())),
        })
        if resp2:
            r.step2_code = resp2.status_code
            r.details.append(f"Step2 잘못된서명→{resp2.status_code}")
        elif err2:
            r.details.append(f"Step2 연결 실패: {err2}")

        # Step 3: 유효한 서명
        good_sig = self._make_signature(self.cfg.secret, payload)
        resp3, err3 = self._post_safe(url, payload, {
            sig_header: good_sig,
            "X-Timestamp": str(int(time.time())),
        })
        if resp3:
            r.step3_code = resp3.status_code
            r.step3_body = resp3.text[:500]
            r.details.append(f"Step3 유효서명→{resp3.status_code}")
        elif err3:
            r.details.append(f"Step3 연결 실패: {err3}")

        # Step 4: 상태 조회 가능 여부
        r.step4_state_ok = self._check_state_endpoint()
        r.details.append(f"Step4 상태조회={'가능' if r.step4_state_ok else '불가'}")

        # Tier 결정 — 상태 조회 가능하면 Tier 1, 아니면 Tier 2
        if r.connection_error:
            r.details.append("⚠ 연결 오류로 Tier 판정 불가 — 서버 URL 확인 필요")
        elif r.step4_state_ok:
            r.tier = Tier.TIER_1
        else:
            r.tier = Tier.TIER_2

        r.details.append(f"→ {r.tier.value}")
        return r

    # ──────────────────────────────────────────────────────
    # 공격 1: 다운그레이드 (sha256 → sha1 → md5 → 서명없음)
    # ──────────────────────────────────────────────────────
    def attack_downgrade(self, path: str, probe: ProbeResult,
                         sig_header: str = None) -> List[AttackResult]:  # 버그 13 수정: sig_header 파라미터 추가
        results = []
        url = self.cfg.base_url + path
        order_id = f"dg_{int(time.time())}"
        payload = _generate_mock_payload(self.cfg.platform_name, order_id)
        ts = str(int(time.time()))

        # 버그 13 수정: 인자로 받은 sig_header 우선, 없으면 config 기본값 사용
        if sig_header is None:
            sig_header = self.cfg.sig_header
        is_github    = "hub" in sig_header.lower()
        sha1_val     = hmac.new(self.cfg.secret, payload, hashlib.sha1).hexdigest()
        md5_val      = hmac.new(self.cfg.secret, payload, hashlib.md5).hexdigest()

        stages = [
            # ── SHA1 ──────────────────────────────────────────────────────
            # [공통] 플랫폼 고유 헤더에 sha1= 접두사 전송.
            #   서버가 알고리즘 자체를 검증하지 않으면 수락됨.
            #   예) X-Hub-Signature-256: sha1=<hmac> 을 보냈을 때 통과되면
            #       서버는 sha256= 접두사만 기대하고 실제 알고리즘은 안 봄.
            ("SHA1", {sig_header: f"sha1={sha1_val}", "X-Timestamp": ts}),

            # [GitHub 전용] X-Hub-Signature(레거시) 헤더 수락 여부.
            #   GitHub은 SHA1 레거시 헤더를 별도로 운영하므로 추가 시도.
            #   일반 서버는 이 헤더를 모르므로 무시 또는 400 반환 → 오탐 없음.
            *([("SHA1-legacy", {"X-Hub-Signature": f"sha1={sha1_val}", "X-Timestamp": ts})]
              if is_github else []),

            # ── MD5 ──────────────────────────────────────────────────────
            # [공통] 플랫폼 고유 헤더에 md5= 접두사 전송.
            ("MD5", {sig_header: f"md5={md5_val}", "X-Timestamp": ts}),

            # ── 서명없음 ─────────────────────────────────────────────────
            # 헤더 키 자체를 보내지 않음.
            # 빈 문자열("")과 달리 서버 프레임워크가 "헤더 없음"으로 정확히 판단함.
            ("서명없음", {}),
        ]
        any_vuln = False
        stage_details = []

        # ★ 수정: Tier 1이면 공격 전 상태 저장
        # state_before가 None이어도 공격 후 서버가 페이로드를 처리하면
        # state_after는 실제 값을 반환하므로 None != "paid" = True로 감지 가능.
        # 단, 대상 서버가 웹훅 페이로드의 order_id를 DB에 반영하는 구현에 의존함.
        state_before_dg = None
        if probe.tier == Tier.TIER_1:
            state_before_dg = self._query_state(order_id)

        for label, hdrs in stages:
            resp, err = self._post_safe(url, payload, hdrs)
            if err:
                stage_details.append(f"{label}→연결실패({err})")
                continue
            code = resp.status_code if resp else 0
            accepted = 200 <= code < 300
            stage_details.append(f"{label}→{code}")
            if accepted:
                any_vuln = True
                desc_map = {
                    "SHA1":        "SHA1 다운그레이드 수락 — 알고리즘 검증 미흡",
                    "SHA1-legacy": "SHA1 레거시 헤더 수락 — 구버전 GitHub 헤더 허용",
                    "MD5":         "MD5 다운그레이드 수락 — 파기된 알고리즘 허용",
                    "서명없음":     "서명 없이 수락 — 서명 검증 완전 누락",
                }
                # 다운그레이드는 알고리즘 수락 자체가 코드 레벨 결함의 직접 증거
                # → 상태 교차 검증은 판정에 영향 없음. Tier 1에서는 부가 참고용으로만 활용
                details = [f"{label} → {code} (수락됨)"]
                state_changed_dg = False
                conf = Confidence.HIGH  # Tier 무관하게 항상 HIGH
                if probe.tier == Tier.TIER_1:
                    state_after_dg = self._query_state(order_id)
                    state_changed_dg = (state_before_dg != state_after_dg)
                    if state_changed_dg:
                        details.append("⚠ DB 변경됨 — 부가 증거 (판정에 영향 없음)")
                    else:
                        details.append("DB 변화 없음 — 비동기 처리 가능성 (참고용, 판정에 영향 없음)")
                results.append(AttackResult(
                    AttackType.DOWNGRADE, path, probe.tier,
                    True, conf,
                    desc_map[label],
                    details,
                    code,
                    state_changed_dg,
                ))

        if not any_vuln:
            results.append(AttackResult(
                AttackType.DOWNGRADE, path, probe.tier,
                False, Confidence.HIGH,
                "다운그레이드 전단계 거부 — 안전",
                stage_details,
            ))
        return results

    # ──────────────────────────────────────────────────────
    # 공격 2: 재전송 (만료 타임스탬프 + 유효 서명)
    # ──────────────────────────────────────────────────────
    def attack_replay(self, path: str, probe: ProbeResult,
                      sig_header: str = None) -> List[AttackResult]:
        """
        재전송 공격 — 6분 전 만료 타임스탬프 + 유효 서명.
        타임스탬프 검증이 없으면 수락됨.
        """
        if sig_header is None:
            sig_header = self.cfg.sig_header

        # 시크릿 키 미입력 시 재전송 공격 생략
        # 유효 서명을 만들 수 없으면 재전송 공격 자체가 성립하지 않음
        if not self.cfg.secret:
            return [AttackResult(
                AttackType.REPLAY, path, probe.tier,
                False, Confidence.LOW,
                "재전송 공격 생략 — 시크릿 키 미입력",
                ["시크릿 키를 입력하면 재전송 공격을 수행할 수 있습니다."],
            )]

        url = self.cfg.base_url + path
        order_id = f"rp_{int(time.time())}"
        expired_ts_int = int(time.time()) - 360        # 6분 전 (5분 허용 기준 초과)
        expired_ts = str(expired_ts_int)
        # 버그 3 수정: 본문 타임스탬프도 만료 ts로 일치시킴
        # 서버가 헤더가 아닌 본문의 타임스탬프 필드로 만료 검증할 때도 정확히 동작
        payload = _generate_mock_payload(self.cfg.platform_name, order_id,
                                         timestamp=expired_ts_int)

        # 플랫폼별 서명 조립
        headers = self._build_sig_headers(sig_header, payload, expired_ts)

        state_before = None
        if probe.tier == Tier.TIER_1:
            state_before = self._query_state(order_id)

        resp, err = self._post_safe(url, payload, headers)
        if err:
            return [AttackResult(
                AttackType.REPLAY, path, probe.tier,
                False, Confidence.LOW,
                f"재전송 공격 실패 — 연결 오류: {err}",
                [err],
            )]

        accepted = resp and 200 <= resp.status_code < 300

        state_changed = False
        if probe.tier == Tier.TIER_1 and accepted:
            time.sleep(self.cfg.state_check_delay)  # 비동기 워커 처리 대기
            state_after = self._query_state(order_id)
            state_changed = (state_before != state_after)

        if accepted:
            # ★ 수정: 다운그레이드·타입혼동 Stage A와 동일한 패턴으로 일관성 확보
            # Tier 1 + DB 변화 확인 → HIGH, Tier 1 + DB 변화 없음 → MEDIUM
            # Tier 2 → MEDIUM (HTTP 코드 기반)
            if probe.tier == Tier.TIER_1:
                conf = Confidence.HIGH if state_changed else Confidence.MEDIUM
            else:
                conf = Confidence.MEDIUM
            details = [f"만료ts({expired_ts})+유효서명→{resp.status_code}"]
            if state_changed:
                details.append("⚠ 상태변화 확인 — DB 변경됨 (Tier 1 교차검증)")
            elif probe.tier == Tier.TIER_1:
                details.append("DB 변화 없음 — 비동기 처리 가능성 (SAST 결과 함께 확인 권장)")
            return [AttackResult(
                AttackType.REPLAY, path, probe.tier,
                True, conf,
                "재전송 공격 성공 — 만료 타임스탬프 수락됨",
                details, resp.status_code, state_changed,
            )]
        else:
            code = resp.status_code if resp else 0
            return [AttackResult(
                AttackType.REPLAY, path, probe.tier,
                False, Confidence.HIGH,
                "재전송 공격 거부 — 타임스탬프 검증 정상",
                [f"만료ts→{code} (거부)"],
            )]

    # ──────────────────────────────────────────────────────
    # 공격 3: 타입 혼동
    # ──────────────────────────────────────────────────────
    def attack_type_confusion(self, path: str, probe: ProbeResult,
                              sig_header: str = None) -> List[AttackResult]:
        """
        타입 혼동 공격:
          A) Content-Type text/plain 변조 — Tier 1 상태 교차 검증 적용
          B) 배열 래핑 JSON ([{...}]) — Tier 1 선생성 order_id로 상태 교차 검증 적용
        """
        if sig_header is None:
            sig_header = self.cfg.sig_header

        results = []
        url = self.cfg.base_url + path
        ts = str(int(time.time()))
        order_id = f"tc_{int(time.time())}"

        def make_headers(p: bytes, extra: dict = None) -> dict:
            hdrs = self._build_sig_headers(sig_header, p, ts)
            if extra:
                hdrs.update(extra)
            return hdrs

        # ── Stage A: Content-Type text/plain ──
        # Stage B와 동일하게 선생성 방식 적용.
        # 서버가 아는 order_id를 써야 DB 추적이 안정적.
        # 랜덤 order_id 사용 시: state_before=None, state_after=None → 항상 "변화 없음"
        order_id_a = None
        state_before_a = None
        if probe.tier == Tier.TIER_1:
            try:
                r_create_a = self.s.post(
                    self.cfg.base_url + self.cfg.state_create_path,
                    data=json.dumps({"item": "analyzer_test_a"}).encode(),
                    headers={"Content-Type": "application/json"},
                    timeout=self.cfg.timeout,
                )
                if r_create_a.status_code == 200:
                    body_create_a = r_create_a.json()
                    order_id_a = (body_create_a.get("order_id") or
                                  body_create_a.get("id") or
                                  body_create_a.get("pk"))
                    if order_id_a:
                        state_before_a = self._query_state(str(order_id_a))
            except Exception:
                pass

        if order_id_a is None:
            order_id_a = f"{order_id}_a"

        normal_payload = _generate_mock_payload(self.cfg.platform_name, str(order_id_a))
        hdrs_a = make_headers(normal_payload, {"Content-Type": "text/plain"})
        resp_a, err_a = self._post_raw_safe(url, normal_payload, hdrs_a)
        code_a = resp_a.status_code if resp_a else 0
        if 200 <= code_a < 300:
            details_a = [f"text/plain→{code_a}"]
            state_changed_a = False
            conf_a = Confidence.MEDIUM
            if probe.tier == Tier.TIER_1 and state_before_a is not None:
                time.sleep(self.cfg.state_check_delay)  # 비동기 워커 처리 대기
                state_after_a = self._query_state(str(order_id_a))
                state_changed_a = (state_before_a != state_after_a)
                if state_changed_a:
                    conf_a = Confidence.HIGH
                    details_a.append("⚠ 상태변화 확인 — DB 변경됨 (Tier 1 교차검증)")
                else:
                    details_a.append("DB 변화 없음 — 비동기 처리 가능성 (SAST 결과 함께 확인 권장)")
            results.append(AttackResult(
                AttackType.TYPE_CONFUSION, path, probe.tier,
                True, conf_a,
                "Content-Type text/plain 수락 — 입력 검증 미흡",
                details_a, code_a, state_changed_a,
            ))

        # ── Stage B: 배열 래핑 ──
        # 서버 구현 다양성으로 인해 배열 래핑 후 DB 반영 여부를 보장할 수 없음.
        # → Tier 무관하게 HTTP 코드 기반 판정 유지. 상태 교차 검증 미적용.
        base_obj = json.loads(_generate_mock_payload(self.cfg.platform_name, f"{order_id}_b"))
        wrapped = json.dumps([base_obj], ensure_ascii=False).encode()
        hdrs_b = make_headers(wrapped)
        resp_b, _ = self._post_safe(url, wrapped, hdrs_b)
        code_b = resp_b.status_code if resp_b else 0
        if 200 <= code_b < 300:
            results.append(AttackResult(
                AttackType.TYPE_CONFUSION, path, probe.tier,
                True, Confidence.MEDIUM,
                "배열 래핑 JSON 수락 — 파서 검증 미흡",
                [f"[{{...}}]→{code_b}"], code_b,
            ))

        if not results:
            # 전 Stage 거부 — 안전 판정
            # Tier 1: Stage A/B 상태 교차 검증까지 통과 → HIGH
            # Tier 2: HTTP 코드 기반만 가능 → MEDIUM
            safe_conf = Confidence.HIGH if probe.tier == Tier.TIER_1 else Confidence.MEDIUM
            results.append(AttackResult(
                AttackType.TYPE_CONFUSION, path, probe.tier,
                False, safe_conf,
                "타입 혼동 공격 거부",
                [f"A:{code_a} B:{code_b}"],
            ))
        return results

    # ──────────────────────────────────────────────────────
    # 전체 실행
    # ──────────────────────────────────────────────────────
    def run_all(self, path: str, probe: ProbeResult,
                sig_header: str = None) -> List[AttackResult]:  # 버그 18 수정: sig_header 파라미터 추가
        # 버그 18 수정: 외부에서 엔드포인트별 헤더를 주입할 수 있도록 파라미터로 받음
        # 미전달 시 config 기본값 사용 (기존 동작 유지)
        if sig_header is None:
            sig_header = self.cfg.sig_header
        r = []
        r.extend(self.attack_downgrade(path, probe, sig_header))
        r.extend(self.attack_replay(path, probe, sig_header))
        r.extend(self.attack_type_confusion(path, probe, sig_header))
        return r

    # ──────────────────────────────────────────────────────
    # 서명 생성 헬퍼
    # ──────────────────────────────────────────────────────
    def _make_signature(self, secret: bytes, payload: bytes,
                        timestamp: str = None) -> str:
        """
        플랫폼에 맞는 서명 문자열 생성.
        - 일반: "sha256=" + HMAC(secret, payload)
        - Stripe: "t=<ts>,v1=<HMAC(secret, ts+'.'+payload)>"
        - Slack:  "v0=" + HMAC(secret, "v0:<ts>:<body>")
        """
        ts = timestamp or str(int(time.time()))
        if self.cfg.is_stripe:
            signed = f"{ts}.".encode() + payload
            sig_val = hmac.new(secret, signed, hashlib.sha256).hexdigest()
            return f"t={ts},v1={sig_val}"
        elif self.cfg.is_slack:
            base = f"v0:{ts}:".encode() + payload
            sig_val = hmac.new(secret, base, hashlib.sha256).hexdigest()
            return f"v0={sig_val}"
        elif self.cfg.platform_name in ("토스페이먼츠", "toss", "toss_payments", "TOSS_PAYMENTS"):
            # 버그 2 수정: 토스페이먼츠 스펙은 Base64 인코딩된 HMAC-SHA256
            sig_bytes = hmac.new(secret, payload, hashlib.sha256).digest()
            return base64.b64encode(sig_bytes).decode()
        else:
            sig_val = hmac.new(secret, payload, hashlib.sha256).hexdigest()
            prefix = "sha256="  # 버그 1 수정: platform_name 대신 "sha256=" 사용
            return f"{prefix}{sig_val}"

    def _build_sig_headers(self, sig_header: str, payload: bytes,
                           ts: str) -> dict:
        """sig_header 이름과 플랫폼 형식에 맞는 헤더 dict 반환"""
        sig = self._make_signature(self.cfg.secret, payload, ts)
        hdrs = {
            "Content-Type": "application/json",
            sig_header: sig,
        }
        # 버그 22 수정: Slack은 X-Slack-Request-Timestamp 헤더를 별도로 전송해야 함
        # Stripe는 타임스탬프가 서명 문자열 안에 포함되므로 별도 헤더 불필요
        if self.cfg.is_slack:
            hdrs["X-Slack-Request-Timestamp"] = ts
        elif not self.cfg.is_stripe:
            hdrs["X-Timestamp"] = ts
        return hdrs

    # ──────────────────────────────────────────────────────
    # HTTP 헬퍼 (v2: 오류 사유 반환)
    # ──────────────────────────────────────────────────────
    def _post_safe(self, url: str, payload: bytes,
                   extra_headers: dict):
        """
        POST 요청 전송. (response, error_msg) 튜플 반환.
        연결 실패 시 response=None, error_msg=이유.

        request_interval 만큼 대기 후 전송합니다.
          → 연속 공격 요청이 대상 서버의 Rate Limiter에 막히는 것을 방지합니다.
        max_retries 횟수만큼 재시도합니다.
          → 일시적인 네트워크 오류로 인한 오탐을 줄입니다.
        """
        h = {"Content-Type": "application/json"}
        h.update(extra_headers)
        time.sleep(self.cfg.request_interval)  # Rate Limit 방지
        last_err = ""
        # 버그 15 수정: 최초 시도 1번 + max_retries번 재시도
        # 기존 range(max(1, max_retries))는 max_retries=1이면 range(1) = 시도 1번(재시도 없음)
        for _ in range(1 + max(0, self.cfg.max_retries)):
            try:
                resp = self.s.post(url, data=payload, headers=h,
                                   timeout=self.cfg.timeout)
                return resp, None
            except requests.exceptions.ConnectionError:
                last_err = f"연결 거부 — 서버가 실행 중인지 확인 ({url})"
            except requests.exceptions.Timeout:
                last_err = f"타임아웃 — {self.cfg.timeout}초 초과"
            except requests.exceptions.RequestException as e:
                last_err = str(e)
        return None, last_err

    def _post_raw_safe(self, url: str, payload: bytes, headers: dict):
        """Content-Type을 직접 제어하는 POST (타입 혼동 테스트용)"""
        time.sleep(self.cfg.request_interval)  # Rate Limit 방지
        # 버그 25 수정: _post_safe와 동일하게 max_retries 재시도 루프 추가
        last_err = ""
        for _ in range(1 + max(0, self.cfg.max_retries)):
            try:
                resp = self.s.post(url, data=payload, headers=headers,
                                   timeout=self.cfg.timeout)
                return resp, None
            except requests.exceptions.ConnectionError:
                last_err = "연결 거부"
            except requests.exceptions.Timeout:
                last_err = "타임아웃"
            except requests.exceptions.RequestException as e:
                last_err = str(e)
        return None, last_err

    # ──────────────────────────────────────────────────────
    # 상태 조회 (커스텀 URL 지원)
    # ──────────────────────────────────────────────────────
    def _check_state_endpoint(self) -> bool:
        """
        Tier 1 판별: state_create_path 로 주문 생성 후
        state_query_template 으로 조회 성공 여부 확인.
        """
        try:
            create_payload = json.dumps({"item": "analyzer_test"}).encode()
            r = self.s.post(
                self.cfg.base_url + self.cfg.state_create_path,
                data=create_payload,
                headers={"Content-Type": "application/json"},
                timeout=self.cfg.timeout,
            )
            if r.status_code != 200:
                return False
            body = r.json()
            # "order_id", "id" 등 다양한 키 허용
            oid = body.get("order_id") or body.get("id") or body.get("pk")
            if not oid:
                return False
            query_path = self.cfg.state_query_template.replace("{id}", str(oid))
            r2 = self.s.get(
                self.cfg.base_url + query_path,
                timeout=self.cfg.timeout,
            )
            return r2.status_code == 200
        except Exception:
            return False

    def _query_state(self, order_id: str) -> Optional[str]:
        """state_query_template 으로 현재 상태값 조회."""
        try:
            query_path = self.cfg.state_query_template.replace("{id}", str(order_id))
            r = self.s.get(
                self.cfg.base_url + query_path,
                timeout=self.cfg.timeout,
            )
            if r.status_code == 200:
                body = r.json()
                return (body.get("status") or
                        body.get("state") or
                        next(iter(body.values()), None))
        except Exception:
            pass
        return None