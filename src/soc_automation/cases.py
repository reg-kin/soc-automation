"""Validate saved evidence and render the fixed, reviewable Cases projection."""

import hashlib
from dataclasses import asdict

from soc_automation.evidence import Reference, Retrieval
from soc_automation.ingestion import encode, field, normalize
from soc_automation.investigation import build, request_identity

RENDERER_VERSION = "soc-case/2"


def literal(value):
    """Quote untrusted evidence without allowing Markdown structure or control characters."""
    import html

    return (
        html.escape(str(value))
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("`", "&#96;")
        .replace("*", "&#42;")
        .replace("_", "&#95;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
    )


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def render(report, alerts):
    """Recompute every finding; arbitrary report prose is never accepted."""
    try:
        ids, fingerprint = request_identity([a["alert_id"] for a in alerts])
        if (
            report["status"] != "completed"
            or report["evidence_gaps"]
            or report["source_alert_ids"] != ids
            or report["request_fingerprint"] != fingerprint
            or report["investigation_id"] != "inv-" + fingerprint
        ):
            raise ValueError
        for alert in alerts:
            normalized = alert["normalized"]
            original = alert["original"]
            rebuilt_alert, _ = normalize(
                original,
                source_id=(normalized["source_alert_id"] if "_source" not in original else None),
            )
            if digest(original) != alert["original_ref"] or asdict(rebuilt_alert) != normalized:
                raise ValueError
        evidence = {}
        for item in report["retrieved_evidence"]:
            ref = Reference(**item["reference"])
            if item["status"] != "found" or digest(item["document"]) != item["sha256"]:
                raise ValueError
            if ref in evidence:
                raise ValueError
            evidence[ref] = Retrieval(ref, "found", item["document"])

        class SavedProvider:
            def retrieve_many(self, refs):
                if set(refs) != set(evidence):
                    raise ValueError
                return [evidence[r] for r in refs]

        rebuilt = build(alerts, SavedProvider())
        for key, value in rebuilt.items():
            if key != "generation_timestamp" and report[key] != value:
                raise ValueError
        priorities = [a["decision"]["priority"] for a in alerts]
        severity = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}[min(priorities)]
        if any(p not in {"P1", "P2", "P3", "P4"} for p in priorities):
            raise ValueError

        def ref(value):
            return literal(value["index"]) + " / " + literal(value["id"])

        actions = sorted(
            {
                str(e["context"]["event.action"])
                for e in report["timeline"]
                if e["context"]["event.action"] is not None
            }
        )
        if not actions:
            actions = sorted(
                {
                    str(category)
                    for event in report["timeline"]
                    for category in (
                        event["context"]["event.category"]
                        if isinstance(event["context"]["event.category"], list)
                        else [event["context"]["event.category"]]
                    )
                    if category is not None
                }
            )
        title = "SOC: " + (", ".join(actions)[:110] if actions else "source event review")
        title += f" ({len(report['timeline'])} events)"
        lines = [
            "Case rendering format: " + RENDERER_VERSION,
            "",
            "## Investigation summary",
            f"Observed {len(report['timeline'])} source events linked to {len(ids)} alerts. "
            f"Triage-derived severity: {severity}. No compromise determination is established.",
            "",
            "## Observed event chronology",
        ]
        for event in report["timeline"]:
            context = (
                "; ".join(
                    literal(k) + " = " + literal(v)
                    for k, v in sorted(event["context"].items())
                    if v is not None
                )
                or "No event context attributes supplied"
            )
            lines.append(
                f"- {literal(event['timestamp'])}: {context}. Evidence: {ref(event['reference'])}."
            )
        lines += ["", "## Evidence-backed findings"]
        for fact in report["observed_facts"]:
            fields = (
                "; ".join(
                    literal(k) + " = " + literal(v)
                    for k, v in sorted(fact["context"].items())
                    if v is not None
                )
                or "No context attributes supplied"
            )
            lines.append(f"- Observed in {ref(fact['reference'])}: {fields}.")
        lines += ["", "## Supported inferences"]
        for inference in report["supported_inferences"]:
            support = ", ".join(literal(k) for k in inference["shared_fields"])
            if inference["parent_entity_reference"]:
                support += "; process entity matches a parent entity reference"
            lines.append(
                "- Identifier association (association_only) between "
                + " and ".join(ref(r) for r in inference["evidence"])
                + ": "
                + support
                + ". This does not establish causation or compromise."
            )
        if not report["supported_inferences"]:
            lines.append("- No identifier associations supported by the saved evidence.")
        lines += [
            "",
            "## Evidence limitations",
            "Only saved source documents and supplied attributes were assessed. "
            "Temporal order and shared identifiers do not establish attack stages or causation. "
            "Absent attributes are unknown; completeness outside the selected evidence is unknown.",
            "",
            "## Unresolved questions",
            *["- " + literal(q) for q in report["unresolved_questions"]],
            "",
            "## Evidence provenance",
            "Investigation ID: " + literal(report["investigation_id"]),
            "Audit correlation ID: " + literal(report["audit_correlation_id"]),
            "Investigation engine: " + literal(report["engine_version"]),
        ]
        for alert, priority in zip(ids, priorities, strict=True):
            lines.append(f"- Source alert: {literal(alert)}; triage priority: {priority}.")
        for item in report["retrieved_evidence"]:
            lines.append(f"- Document: {ref(item['reference'])}; SHA-256: {item['sha256']}.")
            source = item["document"]["_source"]

            if (
                field(source, "labels.synthetic") in (True, "true")
                or field(source, "event.kind") == "synthetic"
                or "synthetic test" in str(field(source, "kibana.alert.rule.name") or "").lower()
            ):
                lines.append("  Synthetic test evidence explicitly identified by source metadata.")
            elif "synthetic" in item["reference"]["index"].lower():
                lines.append(
                    "  Source index labels this as synthetic evidence; "
                    "real activity is not established."
                )
        for link in report["evidence_references"]:
            lines.append(f"- Alert {literal(link['alert_id'])} references {ref(link)}.")
        description = "\n".join(lines)
        marker = "soc-publication-" + digest(
            [report["investigation_id"], RENDERER_VERSION, description]
        )
        if len(title) > 160 or len(description) > 30000:
            raise ValueError
        return {
            "title": title,
            "description": description,
            "owner": "securitySolution",
            "severity": severity,
            "tags": [marker],
            "settings": {"syncAlerts": False},
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
        }
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("Investigation is not eligible for case publication") from None
