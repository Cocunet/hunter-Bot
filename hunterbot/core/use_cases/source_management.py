from hunterbot.core.domain import Source, SourceType
from hunterbot.core.interfaces import SourceRepository


class RegisterSourceUseCase:
    """Registers a new educational resource to later be ingested from."""

    def __init__(self, source_repository: SourceRepository) -> None:
        self._sources = source_repository

    def execute(
        self,
        *,
        name: str,
        source_type: SourceType,
        url: str | None = None,
        license_note: str | None = None,
    ) -> Source:
        existing = self._sources.get_by_name(name)
        if existing is not None:
            raise ValueError(f"a source named {name!r} is already registered")
        source = Source(
            name=name,
            source_type=source_type,
            url=url,
            license_note=license_note,
        )
        return self._sources.add(source)


class ListSourcesUseCase:
    def __init__(self, source_repository: SourceRepository) -> None:
        self._sources = source_repository

    def execute(self, *, enabled_only: bool = False) -> list[Source]:
        return self._sources.list(enabled_only=enabled_only)
