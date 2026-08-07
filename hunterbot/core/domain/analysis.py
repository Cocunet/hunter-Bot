from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from hunterbot.core.domain.enums import Severity


class TriagePriority(str, Enum):
    """How urgently a human reviewer should look at a Finding.

    Distinct from Finding.severity: severity describes the vulnerability
    class in the abstract (a scanner's fixed judgment), while priority is a
    reasoned, per-scan-result call informed by context the scanner itself
    doesn't see (what else was found, how it reads in combination).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class FindingTriage(BaseModel):
    """One Finding's reasoned priority, with the reasoning that produced it."""

    model_config = ConfigDict(frozen=True)

    finding_id: int
    priority: TriagePriority
    reasoning: str = Field(min_length=1)


class AttackChain(BaseModel):
    """A narrative connecting two or more Findings into a bigger risk.

    E.g. an exposed .env file plus a missing authentication check on an
    admin endpoint reads very differently together than either does alone
    — that's the kind of connection this captures. ``finding_ids`` lets a
    caller (report generator, CLI, API response) re-attach the full Finding
    objects it already has rather than embedding them here.
    """

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1, max_length=255)
    finding_ids: tuple[int, ...] = Field(min_length=1)
    narrative: str = Field(min_length=1)
    severity: Severity


class ScanAnalysis(BaseModel):
    """An LLM's reasoning pass over a set of Findings: triage + attack chains.

    Additive, not authoritative: every Finding it references must already
    exist (produced by a ScannerPlugin), and nothing here changes stored
    data — it's a read-only interpretation layer a caller can choose to
    show, store, or ignore.
    """

    model_config = ConfigDict(frozen=True)

    summary: str = Field(min_length=1)
    triage: tuple[FindingTriage, ...] = Field(default_factory=tuple)
    attack_chains: tuple[AttackChain, ...] = Field(default_factory=tuple)
