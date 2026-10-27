"""Deterministic evidence-backed investigation, without detection or correlation rules."""

import hashlib
from datetime import UTC, datetime
from itertools import combinations

from soc_automation.evidence import MAX_REFERENCES, Reference, reference_dict, validate
from soc_automation.ingestion import InputError, encode, field

ENGINE_VERSION = "3.0"
CONTEXT = (
    "process.entity_id",
    "process.parent.entity_id",
    "user.id",
    "session.id",
    "host.id",
    "event.action",
    "event.category",
)


def request_identity(alert_ids):
    if (
        not isinstance(alert_ids, (list, tuple))
        or not alert_ids
        or len(alert_ids) > 100
        or any(not isinstance(x, str) or not x or len(x) > 512 for x in alert_ids)
    ):
        raise InputError("Invalid alert selection")
    ids = sorted(set(alert_ids))
    fingerprint = hashlib.sha256(encode([ENGINE_VERSION, ids]).encode()).hexdigest()
    return ids, fingerprint


def build(alerts, provider):
    references = []
    gaps = []
    for alert in alerts:
        ancestors = alert["normalized"]["ancestors"] or []
        if not ancestors:
            gaps.append({"alert_id": alert["alert_id"], "reason": "no_source_references"})
        for ancestor in ancestors:
            reference = Reference(ancestor.get("index"), ancestor.get("id"))
            references.append({"alert_id": alert["alert_id"], **ancestor})
            if len(references) > MAX_REFERENCES:
                raise InputError("Evidence reference limit exceeded")
    unique = sorted({Reference(r["index"], r["id"]) for r in references})
    results = provider.retrieve_many(unique) if unique else []
    if not isinstance(results, list) or len(results) != len(unique):
        raise InputError("Incomplete provider batch")
    evidence, timeline, facts = [], [], []
    for reference, supplied in zip(unique, results, strict=True):
        result = validate(supplied, reference)
        metadata = {"reference": reference_dict(reference), "status": result.status}
        if result.status != "found":
            gaps.append({**metadata, "reason": result.reason or "retrieval_failed"})
        else:
            document = result.document
            metadata.update(
                document=document, sha256=hashlib.sha256(encode(document).encode()).hexdigest()
            )
            try:
                source = document["_source"]
                context = {key: field(source, key) for key in CONTEXT}
                if any(v is not None and not isinstance(v, (str, list)) for v in context.values()):
                    raise InputError("Invalid context")
                for key in CONTEXT[:5]:
                    if context[key] is not None and (
                        not isinstance(context[key], str) or not context[key].strip()
                    ):
                        raise InputError("Invalid identifier")
                timestamp = field(source, "@timestamp")
                event = {"reference": reference_dict(reference), "context": context}
                facts.append({**event, "kind": "source_context"})
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError
                timeline.append({**event, "timestamp": parsed.astimezone(UTC).isoformat()})
            except (ValueError, TypeError, AttributeError):
                gaps.append(
                    {
                        "reference": reference_dict(reference),
                        "reason": "invalid_context_or_timestamp",
                    }
                )
        evidence.append(metadata)
    timeline.sort(key=lambda e: (e["timestamp"], encode(e["reference"])))
    inferences = []
    for left, right in combinations(facts, 2):
        a, b = left["context"], right["context"]
        supports = [key for key in CONTEXT[:5] if a[key] and a[key] == b[key]]
        parent = bool(
            (a["process.entity_id"] and a["process.entity_id"] == b["process.parent.entity_id"])
            or (b["process.entity_id"] and b["process.entity_id"] == a["process.parent.entity_id"])
        )
        if supports or parent:
            inferences.append(
                {
                    "kind": "identifier_association",
                    "evidence": [left["reference"], right["reference"]],
                    "shared_fields": supports,
                    "parent_entity_reference": parent,
                    "certainty": "association_only",
                    "causation_established": False,
                }
            )
    return {
        "schema_version": 1,
        "engine_version": ENGINE_VERSION,
        "source_alert_ids": sorted(a["alert_id"] for a in alerts),
        "evidence_references": references,
        "retrieved_evidence": evidence,
        "timeline": timeline,
        "observed_facts": facts,
        "supported_inferences": inferences,
        "evidence_gaps": gaps,
        "status": "partial" if gaps else "completed",
        "unresolved_questions": [
            "Do associated events have a causal relationship?",
            "Does the activity represent compromise?",
        ],
        "generation_timestamp": datetime.now(UTC).isoformat(),
    }
