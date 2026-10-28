"""Administrative commands and local or read-only Elasticsearch ingestion."""

import argparse
import json
import logging
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from soc_automation import operator_cli, preparation_coordinator
from soc_automation.config import (
    ConfigurationError,
    ElasticsearchSettings,
    KibanaSettings,
    KibanaTargetSettings,
    Settings,
)
from soc_automation.coordination import InvestigationQueue
from soc_automation.elasticsearch import ElasticsearchProvider
from soc_automation.evidence import FixtureEvidenceProvider, Reference
from soc_automation.ingestion import Limits, encode, parse
from soc_automation.kibana import KibanaClient
from soc_automation.logging import configure_logging
from soc_automation.service import (
    ingest,
    investigate,
    prepare_case,
    publish_case,
    reconcile_case,
)
from soc_automation.state import StateError, Store
from soc_automation.triage import Policy


def _safe_decision(decision: dict) -> dict:
    return {
        key: decision[key]
        for key in (
            "validity",
            "activity",
            "disposition",
            "priority",
            "rationale",
            "policy_fingerprint",
        )
    }


def main(argv: list[str] | None = None) -> int:
    supplied = list(argv) if argv is not None else sys.argv[1:]
    if supplied and supplied[0] in operator_cli.COMMANDS:
        return operator_cli.main(supplied)
    parser = argparse.ArgumentParser(
        description="SOC automation administration and alert ingestion", allow_abbrev=False
    )
    parser.add_argument(
        "command",
        choices=(
            *operator_cli.COMMANDS,
            "list-case-publications",
            "review-case-publication",
            "run-case-preparation",
            "investigation-queue-health",
            "run-investigation-worker",
            "plan-investigations",
            "enqueue-investigations",
            "show-investigation-job",
            "list-investigation-jobs",
            "recover-investigation-jobs",
            "fetch-alert",
            "check-config",
            "init-db",
            "healthcheck",
            "ingest",
            "triage",
            "show-alert",
            "investigate",
            "show-investigation",
            "prepare-case",
            "publish-case",
            "show-case-publication",
            "reconcile-case",
            "validate-kibana",
        ),
    )
    batch = parser.add_mutually_exclusive_group()
    batch.add_argument("--once", action="store_true")
    batch.add_argument(
        "--max-jobs",
        type=int,
        default=None,
        help="Bounded worker batch (1-1000); exit 0 means batch completed",
    )
    parser.add_argument(
        "--review-status", choices=("unreviewed", "approved", "declined", "revoked")
    )
    parser.add_argument("--target", help="Canonical case target, or configured for SOC_KIBANA_URL")
    parser.add_argument("--cursor", help="Continuation cursor from list-case-publications")
    parser.add_argument("--job-id")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--retry-seconds", type=int, default=60)
    parser.add_argument("--discovery-limit", type=int, default=100)
    parser.add_argument("--processing-limit", type=int, default=50)
    parser.add_argument("--recovery-limit", type=int, default=100)
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--index", help="Exact Elasticsearch index for fetch-alert or ingest")
    parser.add_argument("--id", help="Exact Elasticsearch document ID")
    parser.add_argument(
        "--provider",
        choices=("fixture", "elasticsearch"),
        help="Ingest: elasticsearch; investigate: fixture (default) or elasticsearch",
    )
    parser.add_argument("--file", type=Path, help="Local alert export for offline ingestion")
    parser.add_argument("--source-id")
    parser.add_argument("--alert-id", action="append")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--investigation-id")
    parser.add_argument("--publication-id")
    parser.add_argument("--new-revision", action="store_true")
    parser.add_argument("--approve-payload-sha256")
    parser.add_argument("--authorize-case-creation", action="store_true")
    parser.add_argument("--policy", type=Path, help="Trusted operator-owned local policy JSON")
    parser.add_argument("--max-input-bytes", type=int, default=4_194_304)
    parser.add_argument("--max-alert-bytes", type=int, default=262_144)
    parser.add_argument("--max-batch-size", type=int, default=100)
    args = parser.parse_args(argv)
    if args.command in operator_cli.COMMANDS:
        parser.error("operator command must precede its options")
    supplied = argv if argv is not None else sys.argv[1:]
    option_commands = {
        "--review-status": {"list-case-publications"},
        "--target": {"list-case-publications"},
        "--cursor": {"list-case-publications"},
        "--discovery-limit": {"run-case-preparation"},
        "--processing-limit": {"run-case-preparation"},
        "--recovery-limit": {"run-case-preparation"},
        "--lease-seconds": {"run-case-preparation"},
        "--once": {"run-investigation-worker"},
        "--max-jobs": {"run-investigation-worker"},
        "--job-id": {"show-investigation-job"},
        "--limit": {
            "list-case-publications",
            "plan-investigations",
            "enqueue-investigations",
            "list-investigation-jobs",
            "recover-investigation-jobs",
            "investigation-queue-health",
        },
        "--max-attempts": {"enqueue-investigations"},
        "--retry-seconds": {"run-investigation-worker", "recover-investigation-jobs"},
        "--new-revision": {"prepare-case"},
        "--max-input-bytes": {"ingest"},
        "--max-alert-bytes": {"ingest"},
        "--max-batch-size": {"ingest"},
    }
    for option, commands in option_commands.items():
        if (
            any(token.split("=", 1)[0] == option for token in supplied)
            and args.command not in commands
        ):
            parser.error(f"{option} is not valid for {args.command}")
    if args.command == "review-case-publication" and not args.publication_id:
        parser.error("review-case-publication requires --publication-id")
    if args.command == "list-case-publications" and not 1 <= args.limit <= 1000:
        parser.error("limit must be between 1 and 1000")
    if args.command == "show-investigation-job" and not args.job_id:
        parser.error("show-investigation-job requires --job-id")
    if args.command != "ingest" and any(
        value is not None for value in (args.file, args.source_id, args.policy)
    ):
        parser.error("file, source-id and policy options require the ingest command")
    if args.command not in {"show-alert", "triage", "investigate"} and args.alert_id is not None:
        parser.error("alert-id requires show-alert or triage")
    if args.evidence_dir is not None and args.command not in {
        "investigate",
        "run-investigation-worker",
    }:
        parser.error("evidence-dir requires investigate")
    if args.investigation_id is not None and args.command not in {
        "show-investigation",
        "prepare-case",
    }:
        parser.error("investigation-id requires show-investigation")
    if (args.index is not None or args.id is not None) and args.command not in {
        "fetch-alert",
        "ingest",
    }:
        parser.error("index and id require fetch-alert or Elasticsearch ingest")
    if args.provider is not None and args.command not in {
        "investigate",
        "ingest",
        "run-investigation-worker",
    }:
        parser.error("provider requires investigate or ingest")
    if args.command == "ingest":
        if args.provider == "elasticsearch":
            if args.file is not None or args.source_id is not None:
                parser.error("Elasticsearch ingest forbids file and source-id")
            if args.index is None or args.id is None:
                parser.error("Elasticsearch ingest requires index and id")
        elif (
            args.provider is not None
            or args.file is None
            or args.index is not None
            or args.id is not None
        ):
            parser.error("Offline ingest requires file and forbids provider, index and id")
    if args.command == "fetch-alert" and (args.index is None or args.id is None):
        parser.error("fetch-alert requires index and id")
    if (
        args.authorize_case_creation or args.approve_payload_sha256 is not None
    ) and args.command != "publish-case":
        parser.error("approval options require publish-case")
    if args.publication_id is not None and args.command not in {
        "review-case-publication",
        "publish-case",
        "show-case-publication",
        "reconcile-case",
    }:
        parser.error("publication-id requires a publication command")
    logger = configure_logging("INFO")
    try:
        if args.command == "validate-kibana":
            result = KibanaClient(KibanaSettings.from_env()).validate()
            print(json.dumps(result, sort_keys=True))
            return 0
        settings = Settings.from_env()
        logger = configure_logging(settings.log_level)
        store = Store(settings.database_path, settings.database_timeout_seconds)
        if args.command in {"list-case-publications", "review-case-publication"}:
            if args.command == "list-case-publications":
                target = args.target
                if target == "configured":
                    target = KibanaTargetSettings.from_env().target
                result = store.list_case_publications(
                    args.limit, review_status=args.review_status, target=target, cursor=args.cursor
                )
            else:
                result = store.review_case_publication(args.publication_id)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "run-case-preparation":
            result = preparation_coordinator.run_pass(
                store,
                KibanaTargetSettings.from_env().target,
                discovery_limit=args.discovery_limit,
                processing_limit=args.processing_limit,
                recovery_limit=args.recovery_limit,
                lease_seconds=args.lease_seconds,
            )
            print(json.dumps(asdict(result), sort_keys=True))
            return 1 if result.stopped is not None else 0
        if args.command in {
            "plan-investigations",
            "enqueue-investigations",
            "show-investigation-job",
            "list-investigation-jobs",
            "recover-investigation-jobs",
            "investigation-queue-health",
        }:
            queue = InvestigationQueue(store)
            if args.command == "investigation-queue-health":
                result = queue.health(args.limit)
            elif args.command == "plan-investigations":
                result = queue.preview(args.limit)
            elif args.command == "enqueue-investigations":
                result = queue.enqueue(args.limit, max_attempts=args.max_attempts)
            elif args.command == "show-investigation-job":
                result = queue.inspect(args.job_id)
            elif args.command == "list-investigation-jobs":
                result = queue.list_jobs(args.limit)
            else:
                result = {"recovered": queue.recover(args.limit, retry_seconds=args.retry_seconds)}
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command in {
            "prepare-case",
            "publish-case",
            "show-case-publication",
            "reconcile-case",
        }:
            if args.command == "show-case-publication":
                result = store.show_case_publication(args.publication_id)
            elif args.command == "prepare-case":
                result = prepare_case(
                    store,
                    args.investigation_id,
                    KibanaTargetSettings.from_env(),
                    revise=args.new_revision,
                )
            else:
                client = KibanaClient(KibanaSettings.from_env())
                if args.command == "publish-case":
                    result = publish_case(
                        store,
                        args.publication_id,
                        client,
                        approval_hash=args.approve_payload_sha256,
                        authorized=args.authorize_case_creation,
                    )
                else:
                    result = reconcile_case(store, args.publication_id, client)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "fetch-alert":
            provider = ElasticsearchProvider(ElasticsearchSettings.from_env())
            hit = provider.fetch_alert(Reference(args.index, args.id))
            print(
                json.dumps(
                    {
                        "_index": hit["_index"],
                        "_id": hit["_id"],
                        "status": "validated",
                        "persisted": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        elif args.command == "check-config":
            event = "config_valid"
        elif args.command == "init-db":
            store.initialize()
            event = "database_initialized"
        elif args.command == "ingest":
            limits = Limits(args.max_input_bytes, args.max_alert_bytes, args.max_batch_size)
            policy = Policy()
            if args.policy is not None:
                with args.policy.open("rb") as handle:
                    configuration = parse(handle.read(262_145), Limits(input_bytes=262_144))
                if len(configuration) != 1:
                    raise ValueError("One policy required")
                policy = Policy(**configuration[0])
            if args.provider == "elasticsearch":
                provider = ElasticsearchProvider(ElasticsearchSettings.from_env())
                hit = provider.fetch_alert(Reference(args.index, args.id))
                data = encode(hit).encode()
            else:
                try:
                    with args.file.open("rb") as handle:
                        data = handle.read(limits.input_bytes + 1)
                except OSError:
                    store.rejection()
                    raise
            results = ingest(store, data, source_id=args.source_id, limits=limits, policy=policy)
            for row in results:
                row["decision"] = _safe_decision(row["decision"])
            print(json.dumps({"alerts": results}, sort_keys=True))
            return 0
        elif args.command in {"investigate", "run-investigation-worker"}:
            if args.provider == "elasticsearch":
                if args.evidence_dir is not None:
                    raise ValueError("Conflicting evidence options")
                provider = ElasticsearchProvider(ElasticsearchSettings.from_env())
            else:
                if args.evidence_dir is None:
                    raise ValueError("Evidence directory required")
                provider = FixtureEvidenceProvider(args.evidence_dir)
            if args.command == "run-investigation-worker":
                from soc_automation.worker import InvestigationWorker

                result = InvestigationWorker(store, provider, retry_seconds=args.retry_seconds).run(
                    max_jobs=1 if args.max_jobs is None else args.max_jobs
                )
            else:
                result = investigate(store, args.alert_id, provider)
            print(json.dumps(result, sort_keys=True))
            return 0
        elif args.command == "show-investigation":
            result = store.show_investigation(args.investigation_id)
            print(json.dumps(result, sort_keys=True))
            return 0
        elif args.command in {"triage", "show-alert"}:
            if not args.alert_id:
                raise ValueError("Alert identifier required")
            if len(args.alert_id) != 1:
                raise ValueError("One alert required")
            result = store.show_alert(args.alert_id[0])
            result["decision"] = _safe_decision(result["decision"])
            print(json.dumps(result, sort_keys=True))
            return 0
        else:
            store.healthcheck()
            event = "healthcheck_ok"
        logger.info(event)
        return 0
    except (ConfigurationError, StateError, sqlite3.Error, OSError, ValueError, TypeError):
        logger.log(logging.ERROR, "command_failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
