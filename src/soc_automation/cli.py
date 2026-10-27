"""Local-only administrative and offline ingestion commands."""

import argparse
import json
import logging
import sqlite3
from pathlib import Path

from soc_automation.config import ConfigurationError, Settings
from soc_automation.ingestion import Limits, parse
from soc_automation.logging import configure_logging
from soc_automation.service import ingest
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
    parser = argparse.ArgumentParser(description="SOC automation offline administration")
    parser.add_argument(
        "command",
        choices=("check-config", "init-db", "healthcheck", "ingest", "triage", "show-alert"),
    )
    parser.add_argument("--file", type=Path)
    parser.add_argument("--source-id")
    parser.add_argument("--alert-id")
    parser.add_argument("--policy", type=Path, help="Trusted operator-owned local policy JSON")
    parser.add_argument("--max-input-bytes", type=int, default=4_194_304)
    parser.add_argument("--max-alert-bytes", type=int, default=262_144)
    parser.add_argument("--max-batch-size", type=int, default=100)
    args = parser.parse_args(argv)
    if args.command != "ingest" and any(
        value is not None for value in (args.file, args.source_id, args.policy)
    ):
        parser.error("file, source-id and policy options require the ingest command")
    if args.command not in {"show-alert", "triage"} and args.alert_id is not None:
        parser.error("alert-id requires show-alert or triage")
    logger = configure_logging("INFO")
    try:
        settings = Settings.from_env()
        logger = configure_logging(settings.log_level)
        store = Store(settings.database_path, settings.database_timeout_seconds)
        if args.command == "check-config":
            event = "config_valid"
        elif args.command == "init-db":
            store.initialize()
            event = "database_initialized"
        elif args.command == "ingest":
            if args.file is None:
                raise ValueError("File required")
            limits = Limits(args.max_input_bytes, args.max_alert_bytes, args.max_batch_size)
            policy = Policy()
            if args.policy is not None:
                with args.policy.open("rb") as handle:
                    configuration = parse(handle.read(262_145), Limits(input_bytes=262_144))
                if len(configuration) != 1:
                    raise ValueError("One policy required")
                policy = Policy(**configuration[0])
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
        elif args.command in {"triage", "show-alert"}:
            if not args.alert_id:
                raise ValueError("Alert identifier required")
            result = store.show_alert(args.alert_id)
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
