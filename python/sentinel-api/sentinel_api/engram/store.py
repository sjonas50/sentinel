"""Engram storage — abstract interface + file-system implementation."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from sentinel_api.engram.models import Engram, EngramId, EngramQuery


class StoreError(Exception):
    """Base class for engram store errors."""


class NotFoundError(StoreError):
    """Engram not found."""


class IntegrityError(StoreError):
    """Stored engram failed integrity check."""


class NotFinalizedError(StoreError):
    """Engram has no content hash (not finalized)."""


class EngramStore(ABC):
    """Abstract interface for engram persistence backends."""

    @abstractmethod
    def save(self, engram: Engram) -> None:
        """Store a finalized engram."""

    @abstractmethod
    def get(self, engram_id: EngramId) -> Engram:
        """Retrieve an engram by ID, verifying integrity."""

    @abstractmethod
    def list(self, query: EngramQuery) -> list[Engram]:
        """List engrams matching the query, ordered by started_at desc."""


class FileEngramStore(EngramStore):
    """File-system backed engram store.

    Stores engrams as JSON files in a date-partitioned directory tree::

        {root}/YYYY/MM/DD/{session_id}.json
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _engram_path(self, engram: Engram) -> Path:
        date_part = engram.started_at.strftime("%Y/%m/%d")
        return self.root / date_part / f"{engram.id.value}.json"

    def _find_path(self, engram_id: EngramId) -> Path:
        filename = f"{engram_id.value}.json"
        for path in self.root.rglob(filename):
            return path
        raise NotFoundError(f"Engram not found: {engram_id}")

    def save(self, engram: Engram) -> None:
        if engram.content_hash is None:
            raise NotFinalizedError("Engram has no content hash")

        path = self._engram_path(engram)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(engram.model_dump(mode="json"), indent=2)
        )

    def get(self, engram_id: EngramId) -> Engram:
        path = self._find_path(engram_id)
        data = json.loads(path.read_text())
        engram = Engram.model_validate(data)

        if not engram.verify_integrity():
            raise IntegrityError(
                f"Integrity check failed for engram {engram_id}"
            )
        return engram

    def list(self, query: EngramQuery) -> list[Engram]:
        results: list[Engram] = []
        for path in self.root.rglob("*.json"):
            data = json.loads(path.read_text())
            engram = Engram.model_validate(data)
            if self._matches(engram, query):
                results.append(engram)

        results.sort(key=lambda e: e.started_at, reverse=True)
        return results

    @staticmethod
    def _matches(engram: Engram, query: EngramQuery) -> bool:
        if query.tenant_id and engram.tenant_id != query.tenant_id:
            return False
        if query.agent_id and engram.agent_id != query.agent_id:
            return False
        if query.session_id and engram.id != query.session_id:
            return False
        if query.from_time and engram.started_at < query.from_time:
            return False
        return not (query.to_time and engram.started_at > query.to_time)
