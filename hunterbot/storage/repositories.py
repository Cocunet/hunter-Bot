from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from hunterbot.core.domain import (
    KnowledgeItem,
    Scope,
    ScopeStatus,
    Severity,
    Source,
    SourceType,
    VulnerabilityCategory,
    target_matches,
)
from hunterbot.storage.models import KnowledgeItemORM, ScopeORM, SourceORM


def _source_to_domain(row: SourceORM) -> Source:
    return Source(
        id=row.id,
        name=row.name,
        source_type=SourceType(row.source_type),
        url=row.url,
        license_note=row.license_note,
        enabled=row.enabled,
        added_at=row.added_at,
        last_fetched_at=row.last_fetched_at,
    )


def _knowledge_item_to_domain(row: KnowledgeItemORM) -> KnowledgeItem:
    return KnowledgeItem(
        id=row.id,
        source_id=row.source_id,
        category=VulnerabilityCategory(row.category),
        title=row.title,
        summary=row.summary,
        content_hash=row.content_hash,
        cwe=row.cwe,
        owasp_category=row.owasp_category,
        severity_hint=Severity(row.severity_hint) if row.severity_hint else None,
        tags=tuple(row.tags),
        references=tuple(row.references),
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _scope_to_domain(row: ScopeORM) -> Scope:
    return Scope(
        id=row.id,
        target=row.target,
        program_name=row.program_name,
        authorized_by=row.authorized_by,
        notes=row.notes,
        status=ScopeStatus(row.status),
        authorized_at=row.authorized_at,
        expires_at=row.expires_at,
    )


class SqlAlchemySourceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, source: Source) -> Source:
        row = SourceORM(
            name=source.name,
            source_type=source.source_type.value,
            url=source.url,
            license_note=source.license_note,
            enabled=source.enabled,
            added_at=source.added_at,
            last_fetched_at=source.last_fetched_at,
        )
        self._session.add(row)
        self._session.commit()
        self._session.refresh(row)
        return _source_to_domain(row)

    def get(self, source_id: int) -> Source | None:
        row = self._session.get(SourceORM, source_id)
        return _source_to_domain(row) if row else None

    def update(self, source: Source) -> Source:
        if source.id is None:
            raise ValueError("cannot update a source without an id")
        row = self._session.get(SourceORM, source.id)
        if row is None:
            raise ValueError(f"no source with id {source.id}")
        row.name = source.name
        row.source_type = source.source_type.value
        row.url = source.url
        row.license_note = source.license_note
        row.enabled = source.enabled
        row.last_fetched_at = source.last_fetched_at
        self._session.commit()
        self._session.refresh(row)
        return _source_to_domain(row)

    def get_by_name(self, name: str) -> Source | None:
        row = self._session.scalar(select(SourceORM).where(SourceORM.name == name))
        return _source_to_domain(row) if row else None

    def list(self, *, enabled_only: bool = False) -> list[Source]:
        stmt = select(SourceORM)
        if enabled_only:
            stmt = stmt.where(SourceORM.enabled.is_(True))
        rows = self._session.scalars(stmt).all()
        return [_source_to_domain(row) for row in rows]


class SqlAlchemyKnowledgeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, item: KnowledgeItem) -> KnowledgeItem:
        row = KnowledgeItemORM(
            source_id=item.source_id,
            category=item.category.value,
            title=item.title,
            summary=item.summary,
            content_hash=item.content_hash,
            cwe=item.cwe,
            owasp_category=item.owasp_category,
            severity_hint=item.severity_hint.value if item.severity_hint else None,
            tags=list(item.tags),
            references=list(item.references),
            version=item.version,
            created_at=item.created_at,
            updated_at=item.updated_at,
        )
        self._session.add(row)
        self._session.commit()
        self._session.refresh(row)
        return _knowledge_item_to_domain(row)

    def get(self, item_id: int) -> KnowledgeItem | None:
        row = self._session.get(KnowledgeItemORM, item_id)
        return _knowledge_item_to_domain(row) if row else None

    def get_by_content_hash(self, content_hash: str) -> KnowledgeItem | None:
        row = self._session.scalar(
            select(KnowledgeItemORM).where(KnowledgeItemORM.content_hash == content_hash)
        )
        return _knowledge_item_to_domain(row) if row else None

    def list_by_source(self, source_id: int) -> list[KnowledgeItem]:
        rows = self._session.scalars(
            select(KnowledgeItemORM).where(KnowledgeItemORM.source_id == source_id)
        ).all()
        return [_knowledge_item_to_domain(row) for row in rows]

    def search(
        self,
        *,
        keyword: str | None = None,
        category: str | None = None,
        cwe: str | None = None,
        owasp_category: str | None = None,
        severity: str | None = None,
        tag: str | None = None,
    ) -> list[KnowledgeItem]:
        stmt = select(KnowledgeItemORM)
        if category is not None:
            stmt = stmt.where(KnowledgeItemORM.category == category)
        if cwe is not None:
            stmt = stmt.where(KnowledgeItemORM.cwe == cwe)
        if owasp_category is not None:
            stmt = stmt.where(KnowledgeItemORM.owasp_category.ilike(owasp_category))
        if severity is not None:
            stmt = stmt.where(KnowledgeItemORM.severity_hint == severity)
        if keyword is not None:
            like = f"%{keyword}%"
            stmt = stmt.where(
                KnowledgeItemORM.title.ilike(like) | KnowledgeItemORM.summary.ilike(like)
            )
        rows = self._session.scalars(stmt).all()
        items = [_knowledge_item_to_domain(row) for row in rows]
        if tag is not None:
            lowered_tag = tag.lower()
            items = [item for item in items if lowered_tag in (t.lower() for t in item.tags)]
        return items


class SqlAlchemyScopeRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, scope: Scope) -> Scope:
        row = ScopeORM(
            target=scope.target,
            program_name=scope.program_name,
            authorized_by=scope.authorized_by,
            notes=scope.notes,
            status=scope.status.value,
            authorized_at=scope.authorized_at,
            expires_at=scope.expires_at,
        )
        self._session.add(row)
        self._session.commit()
        self._session.refresh(row)
        return _scope_to_domain(row)

    def get(self, scope_id: int) -> Scope | None:
        row = self._session.get(ScopeORM, scope_id)
        return _scope_to_domain(row) if row else None

    def list(self) -> list[Scope]:
        rows = self._session.scalars(select(ScopeORM)).all()
        return [_scope_to_domain(row) for row in rows]

    def find_matching(self, target: str) -> list[Scope]:
        all_scopes = self.list()
        return [scope for scope in all_scopes if target_matches(scope.target, target)]
