import os
from typing import Protocol

from pydantic import BaseModel, Field

from hunterbot.core.domain import KnowledgeItem, Severity, Source, VulnerabilityCategory
from hunterbot.knowledge.extraction.hashing import content_hash

try:
    import anthropic

    _ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatched flag in tests
    _ANTHROPIC_AVAILABLE = False

_DEFAULT_MODEL = "claude-opus-5"
_MODEL_ENV_VAR = "HUNTERBOT_ANTHROPIC_MODEL"
_MAX_TOKENS = 8192
_TITLE_MAX_LENGTH = 255

_SYSTEM_PROMPT = """\
You are a security knowledge extraction assistant for HunterBot, an authorized \
defensive security assessment platform. Given a chunk of text from an educational \
security resource (documentation, write-up, blog post, or paper), identify every \
self-contained piece of vulnerability-relevant knowledge in it: a described \
vulnerability class, attack technique, detection method, or mitigation.

For each one, extract:
- title: a short, specific title (a few words to one sentence)
- summary: a self-contained 1-4 sentence summary of the technique or vulnerability, \
using only information present in the text
- category: the single best-fitting category from the provided list
- cwe: the CWE identifier if explicitly stated in the text (e.g. "CWE-79"), else null
- owasp_category: the OWASP Top 10 category name or code if explicitly stated, else null
- severity_hint: a severity level if the text states or clearly implies one, else null
- tags: a few short keyword tags drawn from the text

Only extract items that are actually about a security vulnerability, attack technique, \
detection method, or mitigation -- skip unrelated prose (navigation text, author bios, \
unrelated commentary). If the text contains no such content, return an empty items list. \
Do not invent facts, CWE numbers, or OWASP mappings that are not supported by the text."""


class LLMExtractionError(RuntimeError):
    """Raised when the LLM-backed extractor cannot produce a result."""


class _ExtractedItem(BaseModel):
    title: str
    summary: str
    category: VulnerabilityCategory
    cwe: str | None = None
    owasp_category: str | None = None
    severity_hint: Severity | None = None
    tags: list[str] = Field(default_factory=list)


class _ExtractionResult(BaseModel):
    items: list[_ExtractedItem]


class _AnthropicClient(Protocol):
    """The slice of the anthropic SDK client this extractor depends on.

    Depending on this Protocol rather than the concrete `anthropic.Anthropic`
    class lets tests inject a fake client without installing the `anthropic`
    package at all.
    """

    messages: object


def _resolve_model(model: str | None) -> str:
    return model or os.environ.get(_MODEL_ENV_VAR) or _DEFAULT_MODEL


class LLMKnowledgeExtractor:
    """LLM-backed KnowledgeExtractor implementation using the Claude API.

    Optional: requires the 'llm' extra (`pip install "hunterbot[llm]"`) and a
    configured Anthropic API key. Implements the same KnowledgeExtractor
    interface as RuleBasedExtractor, so it is a drop-in replacement anywhere
    an extractor is injected (see hunterbot.ingestion.IngestionPipeline) —
    callers never need to know which backend produced a KnowledgeItem.

    Defaults to Claude Opus 5; override via the ``model`` constructor
    argument or the ``HUNTERBOT_ANTHROPIC_MODEL`` environment variable if a
    cheaper model fits a high-volume ingestion workload better.
    """

    def __init__(self, *, model: str | None = None, client: _AnthropicClient | None = None) -> None:
        if client is None:
            if not _ANTHROPIC_AVAILABLE:
                raise LLMExtractionError(
                    "the LLM-backed extractor requires the 'llm' extra: "
                    'pip install "hunterbot[llm]"'
                )
            client = anthropic.Anthropic()
        self._model = _resolve_model(model)
        self._client = client

    def is_available(self) -> bool:
        return _ANTHROPIC_AVAILABLE

    def extract(self, *, text: str, source: Source) -> list[KnowledgeItem]:
        if source.id is None:
            raise ValueError("source must be persisted (have an id) before extraction")
        if not text.strip():
            return []

        try:
            response = self._client.messages.parse(
                model=self._model,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": text}],
                output_format=_ExtractionResult,
            )
        except Exception as exc:
            # Deliberately broad: SDK failures here range from typed
            # anthropic.APIStatusError/APIConnectionError to a raw TypeError
            # raised by the SDK itself when no credentials are configured
            # (discovered by hand — it isn't one of the SDK's own exception
            # classes). Any of them should surface as a clear, catchable
            # error to the ingestion pipeline and CLI rather than a raw
            # traceback from inside the SDK's request internals.
            raise LLMExtractionError(f"Claude API request failed: {exc}") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            return []

        return self._to_knowledge_items(response.parsed_output, source)

    def _to_knowledge_items(self, parsed: _ExtractionResult, source: Source) -> list[KnowledgeItem]:
        items: list[KnowledgeItem] = []
        seen_hashes: set[str] = set()
        for extracted in parsed.items:
            title = extracted.title.strip()[:_TITLE_MAX_LENGTH]
            summary = extracted.summary.strip()
            if not title or not summary:
                continue

            item_hash = content_hash(summary)
            if item_hash in seen_hashes:
                continue
            seen_hashes.add(item_hash)

            items.append(
                KnowledgeItem(
                    source_id=source.id,
                    category=extracted.category,
                    title=title,
                    summary=summary,
                    content_hash=item_hash,
                    cwe=extracted.cwe,
                    owasp_category=extracted.owasp_category,
                    severity_hint=extracted.severity_hint,
                    tags=tuple(extracted.tags),
                )
            )
        return items
