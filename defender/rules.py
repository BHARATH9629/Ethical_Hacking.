"""Detection rules. Each rule receives the current rolling event window (list of
RequestEvent, most-recent last) and the SharedState, and yields Alert objects."""
from collections import defaultdict
from typing import Iterable

from state import Alert, RequestEvent, SharedState

PRIV_ENUM_ACTIONS = {"GetCallerIdentity", "ListAttachedUserPolicies", "ListPolicies",
                     "ListUsers", "ListAccessKeys", "SimulatePrincipalPolicy", "ListRoles"}
EXFIL_ACTIONS = {"GetObject", "Scan", "Query", "ListObjectsV2"}

PRIV_ENUM_THRESHOLD = 3       # calls within window
EXFIL_COUNT_THRESHOLD = 8     # calls within window
EXFIL_BYTES_THRESHOLD = 200_000  # bytes within window


def rule_canary_credential_used(event: RequestEvent, state: SharedState) -> Iterable[Alert]:
    if event.access_key and event.access_key in state.canary_keys:
        key = f"canary:{event.access_key}:{event.service}:{event.action}"
        if state.should_emit(key, cooldown_seconds=1.0):
            yield Alert(
                severity="CRITICAL",
                type="LEAKED_CRED_USED",
                message=f"Leaked credential {event.access_key} used for {event.service}:{event.action}",
                resource=event.resource,
            )


def rule_privilege_enumeration(window: list[RequestEvent], state: SharedState) -> Iterable[Alert]:
    by_key: dict[str, int] = defaultdict(int)
    for e in window:
        if e.action in PRIV_ENUM_ACTIONS and e.access_key:
            by_key[e.access_key] += 1

    for access_key, count in by_key.items():
        if count >= PRIV_ENUM_THRESHOLD and state.should_emit(f"privenum:{access_key}", cooldown_seconds=10.0):
            yield Alert(
                severity="HIGH",
                type="PRIVILEGE_ENUMERATION",
                message=f"Rapid IAM/STS enumeration ({count} calls) by access key {access_key}",
                resource="iam",
            )


def rule_exfiltration_burst(window: list[RequestEvent], state: SharedState) -> Iterable[Alert]:
    by_key_count: dict[str, int] = defaultdict(int)
    by_key_bytes: dict[str, int] = defaultdict(int)
    for e in window:
        if e.action in EXFIL_ACTIONS and e.access_key:
            by_key_count[e.access_key] += 1
            by_key_bytes[e.access_key] += e.bytes

    keys = set(by_key_count) | set(by_key_bytes)
    for access_key in keys:
        count = by_key_count[access_key]
        total_bytes = by_key_bytes[access_key]
        if (count >= EXFIL_COUNT_THRESHOLD or total_bytes >= EXFIL_BYTES_THRESHOLD) and \
                state.should_emit(f"exfil:{access_key}", cooldown_seconds=10.0):
            yield Alert(
                severity="CRITICAL",
                type="EXFILTRATION",
                message=f"Bulk data access burst by {access_key}: {count} calls, {total_bytes} bytes",
                resource="data",
            )


def rule_public_bucket(state: SharedState) -> Iterable[Alert]:
    for bucket in state.public_buckets:
        if state.should_emit(f"public_bucket:{bucket}", cooldown_seconds=30.0):
            yield Alert(
                severity="HIGH",
                type="PUBLIC_BUCKET",
                message=f"Bucket '{bucket}' is publicly readable",
                resource=bucket,
            )


def run_event_rules(event: RequestEvent, window: list[RequestEvent], state: SharedState) -> list[Alert]:
    alerts: list[Alert] = []
    alerts.extend(rule_canary_credential_used(event, state))
    alerts.extend(rule_privilege_enumeration(window, state))
    alerts.extend(rule_exfiltration_burst(window, state))
    return alerts


def run_poll_rules(state: SharedState) -> list[Alert]:
    return list(rule_public_bucket(state))
