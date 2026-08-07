import os
from typing import Protocol

from pydantic import BaseModel, Field

from hunterbot.core.interfaces import ScannerPlugin

try:
    import anthropic

    _ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatched flag in tests
    _ANTHROPIC_AVAILABLE = False

_DEFAULT_MODEL = "claude-opus-5"
_MODEL_ENV_VAR = "HUNTERBOT_ANTHROPIC_MODEL"
_MAX_TOKENS = 2048

_SYSTEM_PROMPT = """\
You are a scan-planning assistant for HunterBot, an authorized defensive security \
assessment platform. You are given a short recon signal (the status, headers, and a \
body snippet from one plain GET request to the target) and a fixed list of already \
vetted, read-only scanner names with short descriptions. Your only job is to pick which \
of those scanners are worth running against this specific target.

You are NOT choosing what requests to make or inventing any new check -- every scanner \
in the list is already safe and bounded regardless of what you pick. You are only \
deciding which of them are likely to find something on this particular target, to avoid \
wasted requests on clearly irrelevant checks (e.g. skip a framework-specific \
info-disclosure check if recon clearly shows a different stack).

Return selected_scanner_names using the exact names given -- never invent a name. When \
in doubt about whether a scanner applies, include it: the cost of running one extra \
read-only check is far lower than missing a real finding. If nothing in the recon signal \
rules any scanner out, select all of them."""


class ScannerSelectionError(RuntimeError):
    """Raised when the LLM-backed scanner selector cannot produce a result."""


class _SelectionResult(BaseModel):
    selected_scanner_names: list[str] = Field(default_factory=list)
    reasoning: str = ""


class _AnthropicClient(Protocol):
    """The slice of the anthropic SDK client this selector depends on.

    See hunterbot.knowledge.extraction.llm_extractor for why this is a
    Protocol rather than the concrete anthropic.Anthropic class: it lets
    tests inject a fake client without installing the anthropic package.
    """

    messages: object


def _resolve_model(model: str | None) -> str:
    return model or os.environ.get(_MODEL_ENV_VAR) or _DEFAULT_MODEL


def _describe(scanner: ScannerPlugin) -> str:
    doc = (type(scanner).__doc__ or "").strip()
    first_line = doc.splitlines()[0] if doc else "(no description)"
    return f"- {scanner.name}: {first_line}"


class LLMScannerSelector:
    """LLM-backed ScannerSelector implementation using the Claude API.

    Optional: requires the 'llm' extra (`pip install "hunterbot[llm]"`) and a
    configured Anthropic API key -- same availability pattern as
    hunterbot.knowledge.extraction.LLMKnowledgeExtractor.

    Only ever narrows RunScanUseCase's fixed scanner list down to a subset
    of itself; see hunterbot.core.interfaces.ScannerSelector for why that
    boundary matters. Any selection failure or an empty/all-invalid result
    is treated as "run everything" by the caller (RunScanUseCase), not as a
    scan failure -- see its docstring.

    Defaults to Claude Opus 5; override via the ``model`` constructor
    argument or the ``HUNTERBOT_ANTHROPIC_MODEL`` environment variable.
    """

    def __init__(self, *, model: str | None = None, client: _AnthropicClient | None = None) -> None:
        if client is None:
            if not _ANTHROPIC_AVAILABLE:
                raise ScannerSelectionError(
                    "adaptive scanning requires the 'llm' extra: pip install \"hunterbot[llm]\""
                )
            client = anthropic.Anthropic()
        self._model = _resolve_model(model)
        self._client = client

    def is_available(self) -> bool:
        return _ANTHROPIC_AVAILABLE

    def select(
        self, *, base_url: str, recon_signal: str, available_scanners: list[ScannerPlugin]
    ) -> list[str]:
        known_names = {scanner.name for scanner in available_scanners}
        if not known_names:
            return []

        scanner_list = "\n".join(_describe(scanner) for scanner in available_scanners)
        prompt = f"Target: {base_url}\n\nRecon signal:\n{recon_signal}\n\nAvailable scanners:\n{scanner_list}"

        try:
            response = self._client.messages.parse(
                model=self._model,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
                output_format=_SelectionResult,
            )
        except Exception as exc:
            # Deliberately broad -- see LLMKnowledgeExtractor.extract for why
            # (SDK failures aren't limited to its own typed exception classes).
            raise ScannerSelectionError(f"Claude API request failed: {exc}") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            return list(known_names)

        selected = [name for name in response.parsed_output.selected_scanner_names if name in known_names]
        return selected or list(known_names)
