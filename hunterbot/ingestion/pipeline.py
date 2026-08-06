from dataclasses import dataclass
from datetime import datetime, timezone

from hunterbot.core.domain import Source
from hunterbot.core.interfaces import KnowledgeExtractor, KnowledgeRepository, SourceRepository
from hunterbot.ingestion.connectors.base import Connector
from hunterbot.ingestion.normalization import normalize


@dataclass(frozen=True)
class IngestionResult:
    source: Source
    items_extracted: int
    items_added: int
    items_deduplicated: int


class IngestionPipeline:
    """Connector fetch -> normalize -> extract -> dedupe -> persist.

    Incremental by design: re-running against unchanged content produces the
    same content_hash for each KnowledgeItem, so already-known items are
    skipped rather than duplicated. Full duplicate/merge handling for
    *changed* content (versioning, diffing) belongs to the learning engine,
    added in a later slice — this pipeline only guards against exact repeats.
    """

    def __init__(
        self,
        *,
        source_repository: SourceRepository,
        knowledge_repository: KnowledgeRepository,
        extractor: KnowledgeExtractor,
    ) -> None:
        self._sources = source_repository
        self._knowledge = knowledge_repository
        self._extractor = extractor

    def ingest(self, *, source: Source, connector: Connector) -> IngestionResult:
        if source.id is None:
            raise ValueError("source must already be registered (have an id) before ingestion")

        raw_document = connector.fetch()
        text = normalize(raw_document.content, content_type=raw_document.content_type)
        extracted = self._extractor.extract(text=text, source=source)

        added = 0
        deduplicated = 0
        for item in extracted:
            if self._knowledge.get_by_content_hash(item.content_hash) is not None:
                deduplicated += 1
                continue
            self._knowledge.add(item)
            added += 1

        updated_source = source.model_copy(update={"last_fetched_at": datetime.now(timezone.utc)})
        self._sources.update(updated_source)

        return IngestionResult(
            source=updated_source,
            items_extracted=len(extracted),
            items_added=added,
            items_deduplicated=deduplicated,
        )
