from dataclasses import dataclass
from datetime import datetime, timezone

from hunterbot.core.domain import Source
from hunterbot.core.interfaces import (
    KnowledgeExtractor,
    KnowledgeRepository,
    KnowledgeRevisionRepository,
    SourceRepository,
)
from hunterbot.ingestion.connectors.base import Connector
from hunterbot.ingestion.normalization import normalize
from hunterbot.learning import KnowledgeDiffEngine, KnowledgeMergeService, MergeAction


@dataclass(frozen=True)
class IngestionResult:
    source: Source
    items_extracted: int
    items_added: int
    items_updated: int
    items_unchanged: int


class IngestionPipeline:
    """Connector fetch -> normalize -> extract -> learn -> persist.

    Incremental by design: extracted items are run through the learning
    engine (hunterbot.learning) rather than a flat content-hash dedupe, so
    re-ingesting a source with revised content updates the matching
    KnowledgeItem in place — archiving its prior version — instead of either
    duplicating it or silently discarding the change.
    """

    def __init__(
        self,
        *,
        source_repository: SourceRepository,
        knowledge_repository: KnowledgeRepository,
        knowledge_revision_repository: KnowledgeRevisionRepository,
        extractor: KnowledgeExtractor,
    ) -> None:
        self._sources = source_repository
        self._extractor = extractor
        self._diff_engine = KnowledgeDiffEngine(knowledge_repository)
        self._merge_service = KnowledgeMergeService(
            knowledge_repository=knowledge_repository,
            revision_repository=knowledge_revision_repository,
        )

    def ingest(self, *, source: Source, connector: Connector) -> IngestionResult:
        if source.id is None:
            raise ValueError("source must already be registered (have an id) before ingestion")

        raw_document = connector.fetch()
        text = normalize(raw_document.content, content_type=raw_document.content_type)
        extracted = self._extractor.extract(text=text, source=source)

        added = updated = unchanged = 0
        for item in extracted:
            diff = self._diff_engine.diff(item)
            result = self._merge_service.apply(diff)
            if result.action == MergeAction.ADDED:
                added += 1
            elif result.action == MergeAction.UPDATED:
                updated += 1
            else:
                unchanged += 1

        updated_source = source.model_copy(update={"last_fetched_at": datetime.now(timezone.utc)})
        self._sources.update(updated_source)

        return IngestionResult(
            source=updated_source,
            items_extracted=len(extracted),
            items_added=added,
            items_updated=updated,
            items_unchanged=unchanged,
        )
