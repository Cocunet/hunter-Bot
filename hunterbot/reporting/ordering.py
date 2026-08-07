from hunterbot.core.domain import Finding, Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first; ties broken by creation order. Shared by every
    report generator so output ordering is consistent across formats."""
    return sorted(findings, key=lambda finding: (_SEVERITY_RANK[finding.severity], finding.created_at))
