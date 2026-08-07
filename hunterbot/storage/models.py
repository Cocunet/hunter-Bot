from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from hunterbot.storage.database import Base
from hunterbot.storage.types import UTCDateTime


class SourceORM(Base):
    __tablename__ = "sources"
    __table_args__ = (UniqueConstraint("name", name="uq_sources_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    license_note: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_fetched_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    knowledge_items: Mapped[list["KnowledgeItemORM"]] = relationship(back_populates="source")


class KnowledgeItemORM(Base):
    __tablename__ = "knowledge_items"
    __table_args__ = (UniqueConstraint("content_hash", name="uq_knowledge_items_content_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity_hint: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    source: Mapped["SourceORM"] = relationship(back_populates="knowledge_items")


class KnowledgeItemRevisionORM(Base):
    __tablename__ = "knowledge_item_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    knowledge_item_id: Mapped[int] = mapped_column(ForeignKey("knowledge_items.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity_hint: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    superseded_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class ScopeORM(Base):
    __tablename__ = "scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    program_name: Mapped[str] = mapped_column(String(255), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_asset: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    location: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    knowledge_source_id: Mapped[int | None] = mapped_column(ForeignKey("knowledge_items.id"), nullable=True)
    scanner_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
