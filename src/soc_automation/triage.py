"""Deterministic local policy. No submitted field grants trusted test status."""

import hashlib
import json
from dataclasses import asdict, dataclass, field

from soc_automation.ingestion import NormalizedAlert, encode

PRIORITIES = {"P1", "P2", "P3", "P4"}


@dataclass(frozen=True)
class Policy:
    version: str = "2.0"
    approved_test_rule_ids: tuple[str, ...] = ()
    asset_criticality: dict[str, str] = field(default_factory=dict)
    asset_priorities: dict[str, str] = field(default_factory=dict)
    rule_overrides: dict[str, str] = field(default_factory=dict)
    severity_priorities: dict[str, str] = field(
        default_factory=lambda: {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
    )
    risk_thresholds: tuple[float, float, float] = (90, 70, 40)
    default_priority: str = "P3"

    def __post_init__(self):
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("Policy version required")
        if not isinstance(self.approved_test_rule_ids, (list, tuple)) or any(
            not isinstance(x, str) or not x for x in self.approved_test_rule_ids
        ):
            raise ValueError("Invalid approved test rules")
        for mapping in (self.asset_priorities, self.rule_overrides, self.severity_priorities):
            if not isinstance(mapping, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) or v not in PRIORITIES
                for k, v in mapping.items()
            ):
                raise ValueError("Invalid priority mapping")
        if not isinstance(self.asset_criticality, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or v not in self.severity_priorities
            for k, v in self.asset_criticality.items()
        ):
            raise ValueError("Invalid asset criticality")
        if set(self.severity_priorities) != {"critical", "high", "medium", "low"}:
            raise ValueError("Incomplete severity policy")
        if not isinstance(self.default_priority, str) or self.default_priority not in PRIORITIES:
            raise ValueError("Invalid default priority")
        if (
            not isinstance(self.risk_thresholds, (tuple, list))
            or len(self.risk_thresholds) != 3
            or any(type(x) not in (int, float) or not 0 <= x <= 100 for x in self.risk_thresholds)
            or not self.risk_thresholds[0] > self.risk_thresholds[1] > self.risk_thresholds[2]
        ):
            raise ValueError("Invalid risk thresholds")


def decide(alert: NormalizedAlert, policy: Policy | None = None) -> dict:
    policy = policy or Policy()
    candidates = []
    reasons = []
    if alert.severity is not None:
        candidates.append(policy.severity_priorities[alert.severity])
        reasons.append("elastic_severity")
    if alert.risk_score is not None:
        candidates.append(
            next(
                (
                    f"P{i}"
                    for i, threshold in enumerate(policy.risk_thresholds, 1)
                    if alert.risk_score >= threshold
                ),
                "P4",
            )
        )
        reasons.append("elastic_risk_score")
    for key in ("host.id", "host.name"):
        asset = alert.entities[key]
        if asset in policy.asset_criticality:
            candidates.append(policy.severity_priorities[policy.asset_criticality[asset]])
            reasons.append("configured_asset_criticality")
        if asset in policy.asset_priorities:
            candidates.append(policy.asset_priorities[asset])
            reasons.append("configured_asset_criticality")
    priority = min(candidates) if candidates else policy.default_priority
    if not candidates:
        reasons.append("missing_priority_context_default")
    if alert.rule_id in policy.rule_overrides:
        priority = policy.rule_overrides[alert.rule_id]
        reasons.append("explicit_rule_override")
    test = alert.rule_id in policy.approved_test_rule_ids
    incomplete = not any(v is not None for v in alert.entities.values())
    disposition = (
        "TEST_ONLY"
        if test
        else "URGENT_INVESTIGATION"
        if priority in {"P1", "P2"}
        else "MANUAL_REVIEW"
        if incomplete
        else "INVESTIGATE"
    )
    reasons.append(
        "approved_test_rule"
        if test
        else "incomplete_entity_evidence"
        if incomplete
        else "investigation_required"
    )
    return {
        "validity": "VALID",
        "activity": "APPROVED_TEST" if test else "UNKNOWN",
        "disposition": disposition,
        "priority": priority,
        "policy_version": policy.version,
        "policy_snapshot": json.loads(encode(asdict(policy))),
        "rationale": reasons,
        "policy_fingerprint": hashlib.sha256(encode(asdict(policy)).encode()).hexdigest(),
    }
