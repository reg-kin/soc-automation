"""Bounded offline JSON ingestion and independently testable normalisation."""

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from soc_automation.state import _identifier


class InputError(ValueError):
    """Input rejected; messages deliberately contain no submitted values."""


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 4_194_304
    alert_bytes: int = 262_144
    batch_size: int = 100
    depth: int = 32

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= 16_777_216 for v in asdict(self).values()):
            raise ValueError("Invalid ingestion limits")


def encode(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def field(document: dict, path: str) -> Any:
    """Resolve dotted and nested ECS forms; reject ambiguous conflicting representations."""
    matches = []
    if path in document:
        matches.append(document[path])
    head, sep, tail = path.partition(".")
    if sep and isinstance(document.get(head), dict):
        nested = field(document[head], tail)
        if nested is not None:
            matches.append(nested)
    if len(matches) > 1 and matches[0] != matches[1]:
        raise InputError("Conflicting field representations")
    return matches[0] if matches else None


def _safe(value: Any, depth: int):
    if depth < 0:
        raise InputError("Nesting limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or any(ord(c) < 32 for c in key):
                raise InputError("Invalid object key")
            _safe(child, depth - 1)
    elif isinstance(value, list):
        for child in value:
            _safe(child, depth - 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise InputError("Nonfinite number")
    elif not (value is None or isinstance(value, (str, int, float, bool))):
        raise InputError("Unexpected value")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON key")
        result[key] = value
    return result


def parse(data: bytes, limits: Limits | None = None) -> list[dict]:
    limits = limits or Limits()
    if len(data) > limits.input_bytes:
        raise InputError("Input size exceeded")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
        _safe(value, limits.depth)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise InputError("Invalid JSON input") from exc
    if isinstance(value, dict) and isinstance(value.get("hits"), dict):
        value = value["hits"].get("hits")
    batch = value if isinstance(value, list) else [value]
    if not batch or len(batch) > limits.batch_size or any(not isinstance(x, dict) for x in batch):
        raise InputError("Invalid batch")
    return batch


@dataclass(frozen=True)
class NormalizedAlert:
    source_system: str
    source_alert_id: str
    source_index: str | None
    rule_id: str | None
    rule_name: str | None
    detection_timestamp: str
    severity: str | None
    risk_score: float | None
    entities: dict[str, str | int | None]
    ancestors: list[dict[str, Any]] | None
    context: dict[str, Any]
    original_ref: str


def normalize(
    item: dict, *, source_id: str | None = None, limits: Limits | None = None
) -> tuple[NormalizedAlert, str]:
    limits = limits or Limits()
    if not isinstance(item, dict):
        raise InputError("Alert must be an object")
    _safe(item, limits.depth)
    original = encode(item)
    if len(original.encode()) > limits.alert_bytes:
        raise InputError("Alert size exceeded")
    wrapped = any(k in item for k in ("_source", "_id", "_index"))
    try:
        if wrapped:
            if source_id is not None:
                raise InputError("Explicit identity conflicts with wrapper")
            identifier = _identifier(item.get("_id"), 512)
            index = _identifier(item.get("_index"), 512)
            document = item.get("_source")
        else:
            identifier = _identifier(source_id, 512)
            index = None
            document = item
    except ValueError as exc:
        raise InputError("Invalid source identity") from exc
    if not isinstance(document, dict):
        raise InputError("Alert document must be an object")
    timestamp = field(document, "@timestamp")
    try:
        if (
            not isinstance(timestamp, str)
            or datetime.fromisoformat(timestamp.replace("Z", "+00:00")).tzinfo is None
        ):
            raise ValueError
    except ValueError as exc:
        raise InputError("Required timestamp must include timezone") from exc
    severity = field(document, "kibana.alert.severity")
    if severity is not None and severity not in ("low", "medium", "high", "critical"):
        raise InputError("Invalid severity")
    risk = field(document, "kibana.alert.risk_score")
    if risk is not None and (type(risk) not in (int, float) or not 0 <= risk <= 100):
        raise InputError("Invalid risk score")
    rule_id = field(document, "kibana.alert.rule.rule_id")
    rule_name = field(document, "kibana.alert.rule.name")
    for value in (rule_id, rule_name):
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise InputError("Invalid rule identifier or name")
    ancestors = field(document, "kibana.alert.ancestors")
    if isinstance(ancestors, dict):
        ancestors = [ancestors]
    if ancestors is not None and (
        not isinstance(ancestors, list) or any(not isinstance(a, dict) for a in ancestors)
    ):
        raise InputError("Invalid ancestors")
    if ancestors is not None:
        for ancestor in ancestors:
            for key in ("id", "index", "type"):
                if key in ancestor and not isinstance(ancestor[key], str):
                    raise InputError("Invalid ancestor reference")
            if "depth" in ancestor and (
                type(ancestor["depth"]) is not int or ancestor["depth"] < 0
            ):
                raise InputError("Invalid ancestor depth")
    context = {
        "rule": {k: v for k, v in document.items() if k.startswith("kibana.alert.rule.")}
        or field(document, "kibana.alert.rule")
    }
    for key in ("host", "user", "process", "event"):
        nested = document.get(key)
        if nested is not None and not isinstance(nested, dict):
            raise InputError("Invalid context object")
        context[key] = {
            k: v for k, v in document.items() if k == key or k.startswith(key + ".")
        } or None
    entities = {}
    for path in (
        "host.id",
        "host.name",
        "user.id",
        "user.name",
        "process.entity_id",
        "process.pid",
    ):
        value = field(document, path)
        if value is not None:
            if path == "process.pid":
                if type(value) is not int or value < 0:
                    raise InputError("Invalid process identifier")
            elif not isinstance(value, str) or not value.strip():
                raise InputError("Invalid entity identifier")
        entities[path] = value
    digest = hashlib.sha256(original.encode()).hexdigest()
    return NormalizedAlert(
        "elastic_security",
        identifier,
        index,
        rule_id,
        rule_name,
        timestamp,
        severity,
        risk,
        entities,
        ancestors,
        context,
        digest,
    ), original
