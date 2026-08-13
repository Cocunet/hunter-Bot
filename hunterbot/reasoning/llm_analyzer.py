import os
from typing import Protocol

from pydantic import BaseModel, Field

from hunterbot.core.domain import (
    AttackChain,
    Finding,
    FindingTriage,
    KnowledgeItem,
    ScanAnalysis,
    Severity,
    TriagePriority,
)

try:
    import anthropic

    _ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatched flag in tests
    _ANTHROPIC_AVAILABLE = False

_DEFAULT_MODEL = "claude-opus-5"
_MODEL_ENV_VAR = "HUNTERBOT_ANTHROPIC_MODEL"
_MAX_TOKENS = 8192

_SYSTEM_PROMPT = """\
You are a security triage assistant for HunterBot, an authorized defensive security \
assessment platform. You are given a list of Findings a set of automated scanners \
already produced for one authorized target, each with a numeric id. Your job is purely \
interpretive: you do not test anything yourself, only reason about what's already there.

Produce two things:

1. Per-finding triage: for every finding id given, assign a priority --
   critical / high / medium / low / likely_false_positive -- reflecting how urgently a
   human reviewer should look at it, plus a short reasoning sentence. Base this on
   context the scanner that produced it couldn't see: how exploitable it plausibly is
   in combination with everything else you were given, not just its standalone
   severity label (which you should treat as one input, not the final answer).

2. Attack chains: identify combinations of two or more findings that, together, reveal
   a bigger risk than any of them individually (e.g. an exposed configuration file plus
   a missing authentication check on a related endpoint). Only report chains you can
   justify from the given findings -- if there are none, return an empty list. Reference
   findings by their given numeric id in finding_ids.

Also write a short overall summary (2-4 sentences) of the target's risk picture.

Do not invent findings, ids, or facts not supported by what you were given. Do not \
suggest or describe how to actually exploit anything -- describe risk, not a how-to."""


class LLMAnalysisError(RuntimeError):
    """Raised when the LLM-backed analyzer cannot produce a result."""


class _FindingTriageItem(BaseModel):
    finding_id: int
    priority: TriagePriority
    reasoning: str


class _AttackChainItem(BaseModel):
    title: str
    finding_ids: list[int]
    narrative: str
    severity: Severity


class _AnalysisResult(BaseModel):
    summary: str
    triage: list[_FindingTriageItem] = Field(default_factory=list)
    attack_chains: list[_AttackChainItem] = Field(default_factory=list)


class _AnthropicClient(Protocol):
    """The slice of the anthropic SDK client this analyzer depends on.

    See hunterbot.knowledge.extraction.llm_extractor for why this is a
    Protocol rather than the concrete anthropic.Anthropic class: it lets
    tests inject a fake client without installing the anthropic package.
    """

    messages: object


def _resolve_model(model: str | None) -> str:
    return model or os.environ.get(_MODEL_ENV_VAR) or _DEFAULT_MODEL


def _render_findings(findings: list[Finding]) -> str:
    lines = []
    for finding in findings:
        lines.append(
            f"id={finding.id} | {finding.severity.value.upper()} | {finding.category.value} | "
            f"{finding.title}\n"
            f"  confidence={finding.confidence.value}, asset={finding.affected_asset}, "
            f"location={finding.location}\n"
            f"  description: {finding.description}"
            + (f"\n  evidence: {finding.evidence}" if finding.evidence else "")
        )
    return "\n".join(lines)


def _render_knowledge_context(items: list[KnowledgeItem]) -> str:
    lines = [f"- ({item.category.value}) {item.title}: {item.summary}" for item in items]
    return "\n".join(lines)


class LLMFindingAnalyzer:
    """LLM-backed FindingAnalyzer implementation using the Claude API.

    Optional: requires the 'llm' extra (`pip install "hunterbot[llm]"`) and a
    configured Anthropic API key -- same availability pattern as
    hunterbot.knowledge.extraction.LLMKnowledgeExtractor. Read-only: this
    reasons about Findings that already exist, it never causes new scanning
    or any other side effect.

    Defaults to Claude Opus 5; override via the ``model`` constructor
    argument or the ``HUNTERBOT_ANTHROPIC_MODEL`` environment variable.
    """

    def __init__(self, *, model: str | None = None, client: _AnthropicClient | None = None) -> None:
        if client is None:
            if not _ANTHROPIC_AVAILABLE:
                raise LLMAnalysisError(
                    "the LLM-backed analyzer requires the 'llm' extra: pip install \"hunterbot[llm]\""
                )
            client = anthropic.Anthropic()
        self._model = _resolve_model(model)
        self._client = client

    def is_available(self) -> bool:
        return _ANTHROPIC_AVAILABLE

    def analyze(
        self, *, findings: list[Finding], knowledge_context: list[KnowledgeItem] | None = None
    ) -> ScanAnalysis:
        if not findings:
            return ScanAnalysis(summary="No findings to analyze.")

        prompt = f"Findings:\n{_render_findings(findings)}"
        if knowledge_context:
            prompt += f"\n\nRelated knowledge base entries:\n{_render_knowledge_context(knowledge_context)}"

        try:
            response = self._client.messages.parse(
                model=self._model,
                max_tokens=_MAX_TOKENS,
                system=_SYSTEM_PROMPT,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
                output_format=_AnalysisResult,
            )
        except Exception as exc:
            # Deliberately broad -- see LLMKnowledgeExtractor.extract for why
            # (SDK failures aren't limited to its own typed exception classes).
            raise LLMAnalysisError(f"Claude API request failed: {exc}") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            return ScanAnalysis(summary="Analysis declined by the model's safety policy.")

        return self._to_scan_analysis(response.parsed_output, findings)

    def _to_scan_analysis(self, parsed: _AnalysisResult, findings: list[Finding]) -> ScanAnalysis:
        known_ids = {finding.id for finding in findings}

        triage = tuple(
            FindingTriage(finding_id=item.finding_id, priority=item.priority, reasoning=item.reasoning)
            for item in parsed.triage
            if item.finding_id in known_ids
        )

        attack_chains = []
        for chain in parsed.attack_chains:
            valid_ids = tuple(fid for fid in chain.finding_ids if fid in known_ids)
            if not valid_ids:
                continue
            attack_chains.append(
                AttackChain(
                    title=chain.title,
                    finding_ids=valid_ids,
                    narrative=chain.narrative,
                    severity=chain.severity,
                )
            )

        return ScanAnalysis(summary=parsed.summary, triage=triage, attack_chains=tuple(attack_chains))
