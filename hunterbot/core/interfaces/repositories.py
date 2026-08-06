from __future__ import annotations

from typing import Protocol

from hunterbot.core.domain import KnowledgeItem, Scope, Source


class SourceRepository(Protocol):
    """Persistence contract for registered educational Sources."""

    def add(self, source: Source) -> Source:
        """Persist a new source and return it with its assigned id."""
        ...

    def get(self, source_id: int) -> Source | None: ...

    def list(self, *, enabled_only: bool = False) -> list[Source]: ...

    def get_by_name(self, name: str) -> Source | None: ...


class KnowledgeRepository(Protocol):
    """Persistence contract for structured KnowledgeItems."""

    def add(self, item: KnowledgeItem) -> KnowledgeItem:
        """Persist a new knowledge item and return it with its assigned id."""
        ...

    def get(self, item_id: int) -> KnowledgeItem | None: ...

    def get_by_content_hash(self, content_hash: str) -> KnowledgeItem | None:
        """Look up an existing item by content hash, for dedupe checks."""
        ...

    def list_by_source(self, source_id: int) -> list[KnowledgeItem]: ...

    def search(self, *, keyword: str | None = None, category: str | None = None) -> list[KnowledgeItem]: ...


class ScopeRepository(Protocol):
    """Persistence contract for authorized scan Scopes."""

    def add(self, scope: Scope) -> Scope:
        """Persist a new scope and return it with its assigned id."""
        ...

    def get(self, scope_id: int) -> Scope | None: ...

    def list(self) -> list[Scope]: ...

    def find_matching(self, target: str) -> list[Scope]:
        """Return all scopes whose ``target`` could authorize the given value."""
        ...
