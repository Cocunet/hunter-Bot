from datetime import datetime, timezone
from pathlib import Path

from hunterbot.core.domain import Finding
from hunterbot.reporting.ordering import sort_findings


def _finding_section(finding: Finding) -> str:
    lines = [
        f"## [{finding.severity.value.upper()}] {finding.title}",
        "",
        f"- **Category:** {finding.category.value}",
        f"- **Confidence:** {finding.confidence.value}",
        f"- **Affected asset:** {finding.affected_asset}",
        f"- **Location:** {finding.location}",
        f"- **Scanner:** {finding.scanner_name}",
        f"- **Detected:** {finding.created_at.isoformat()}",
    ]
    if finding.knowledge_source_id is not None:
        lines.append(f"- **Knowledge source:** KnowledgeItem #{finding.knowledge_source_id}")
    lines += ["", "**Description**", "", finding.description]
    if finding.evidence:
        lines += ["", "**Evidence**", "", finding.evidence]
    if finding.reproduction_steps:
        lines += ["", "**Reproduction**", "", finding.reproduction_steps]
    if finding.impact:
        lines += ["", "**Impact**", "", finding.impact]
    if finding.remediation:
        lines += ["", "**Remediation**", "", finding.remediation]
    if finding.references:
        lines += ["", "**References**", ""]
        lines += [f"- {reference}" for reference in finding.references]
    return "\n".join(lines)


class MarkdownReportGenerator:
    format_name = "markdown"

    def generate(self, *, findings: list[Finding], output_path: Path) -> Path:
        ordered = sort_findings(findings)
        generated_at = datetime.now(timezone.utc).isoformat()

        header = "\n".join(
            [
                "# HunterBot Vulnerability Report",
                "",
                f"Generated: {generated_at}",
                f"Total findings: {len(ordered)}",
            ]
        )
        body = "\n\n---\n\n".join(_finding_section(finding) for finding in ordered)
        document = f"{header}\n\n" + (body if body else "_No findings._\n")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")
        return output_path
