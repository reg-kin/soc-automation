"""Bounded exact-identity offline evidence retrieval; no network transport."""

import hashlib
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from soc_automation.ingestion import InputError, Limits, encode, parse

MAX_REFERENCES = 100


class RetrievalCode(StrEnum):
    SUCCESS = "success"
    MISSING = "missing"
    TRANSPORT = "transport"
    RATE_LIMIT = "rate_limit"
    SERVER = "server"
    AUTH = "auth"
    CONFIGURATION = "configuration"
    INVALID_REFERENCE = "invalid_reference"
    CONFLICT = "conflict"
    INVALID_EVIDENCE = "invalid_evidence"


class InvalidReference(InputError):
    code = RetrievalCode.INVALID_REFERENCE


@dataclass(frozen=True, order=True)
class Reference:
    index: str
    id: str

    def __post_init__(self):
        for value in (self.index, self.id):
            if (
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,512}", value)
                or value in {".", ".."}
            ):
                raise InvalidReference("Unsafe evidence reference")


@dataclass(frozen=True)
class Retrieval:
    reference: Reference
    status: str
    document: dict | None = None
    reason: str | None = None

    @property
    def code(self):
        """Map fixed provider protocol codes, never exception diagnostics."""
        if self.status == "found":
            return RetrievalCode.SUCCESS
        if self.status == "missing":
            return RetrievalCode.MISSING
        return {
            "transport_failure": RetrievalCode.TRANSPORT,
            "connection_timeout": RetrievalCode.TRANSPORT,
            "read_timeout": RetrievalCode.TRANSPORT,
            "rate_limited": RetrievalCode.RATE_LIMIT,
            "server_error": RetrievalCode.SERVER,
            "authentication_failed": RetrievalCode.AUTH,
            "authorization_failed": RetrievalCode.AUTH,
            "tls_verification_failed": RetrievalCode.CONFIGURATION,
            "index_not_permitted": RetrievalCode.INVALID_REFERENCE,
            "identity_or_document_invalid": RetrievalCode.CONFLICT,
        }.get(self.reason, RetrievalCode.INVALID_EVIDENCE)


def validate(result: Retrieval, reference: Reference) -> Retrieval:
    if result.reference != reference or result.status not in {"found", "missing", "failed"}:
        raise InputError("Invalid provider result")
    if result.status == "found":
        item = result.document
        if (
            not isinstance(item, dict)
            or item.get("_index") != reference.index
            or item.get("_id") != reference.id
            or not isinstance(item.get("_source"), dict)
        ):
            return Retrieval(reference, "failed", reason="identity_or_document_invalid")
        # Reuse the bounded parser even for alternative provider implementations.
        parse(encode(item).encode(), Limits(input_bytes=262_144))
    elif result.document is not None:
        raise InputError("Unexpected provider document")
    return result


class EvidenceProvider(Protocol):
    def retrieve(self, reference: Reference) -> Retrieval: ...

    def retrieve_many(self, references: list[Reference]) -> list[Retrieval]: ...


class FixtureEvidenceProvider:
    """Files named SHA256(canonical [index,id]).json contain exported source hits."""

    def __init__(self, directory: Path):
        self.directory = Path(directory).resolve(strict=True)
        if not self.directory.is_dir():
            raise InputError("Evidence directory required")

    @staticmethod
    def filename(reference: Reference) -> str:
        return (
            hashlib.sha256(encode([reference.index, reference.id]).encode()).hexdigest() + ".json"
        )

    def retrieve(self, reference: Reference) -> Retrieval:
        path = self.directory / self.filename(reference)
        try:
            if path.is_symlink():
                raise InputError("Symlink evidence rejected")
            with path.open("rb") as handle:
                items = parse(handle.read(262_145), Limits(input_bytes=262_144, batch_size=1))
            return validate(Retrieval(reference, "found", items[0]), reference)
        except FileNotFoundError:
            return Retrieval(reference, "missing", reason="document_missing")
        except (OSError, ValueError, TypeError):
            return Retrieval(reference, "failed", reason="retrieval_or_validation_failed")

    def retrieve_many(self, references: list[Reference]) -> list[Retrieval]:
        if not references or len(references) > MAX_REFERENCES:
            raise InputError("Evidence batch limit exceeded")
        return [self.retrieve(reference) for reference in references]


def reference_dict(reference: Reference) -> dict:
    return asdict(reference)
