from datetime import datetime, timezone
from html import escape
from pathlib import Path

from hunterbot.core.domain import Finding
from hunterbot.reporting.ordering import sort_findings

_SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#4b5563",
}

_STYLE = """
body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #111827; }
h1 { border-bottom: 2px solid #111827; padding-bottom: 0.5rem; }
.meta { color: #4b5563; margin-bottom: 2rem; }
.finding { border: 1px solid #d1d5db; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
.finding h2 { margin-top: 0; }
.severity-badge { display: inline-block; color: #fff; padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.85rem; font-weight: 600; margin-right: 0.5rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
dt { font-weight: 600; color: #374151; }
dd { margin: 0; }
.section-title { font-weight: 600; margin-top: 1rem; }
pre { background: #f3f4f6; padding: 0.75rem; border-radius: 6px; white-space: pre-wrap; }
"""


def _finding_html(finding: Finding) -> str:
    severity = finding.severity.value
    color = _SEVERITY_COLORS.get(severity, "#4b5563")
    rows = [
        f"<dt>Category</dt><dd>{escape(finding.category.value)}</dd>",
        f"<dt>Confidence</dt><dd>{escape(finding.confidence.value)}</dd>",
        f"<dt>Affected asset</dt><dd>{escape(finding.affected_asset)}</dd>",
        f"<dt>Location</dt><dd>{escape(finding.location)}</dd>",
        f"<dt>Scanner</dt><dd>{escape(finding.scanner_name)}</dd>",
        f"<dt>Detected</dt><dd>{escape(finding.created_at.isoformat())}</dd>",
    ]
    if finding.knowledge_source_id is not None:
        rows.append(f"<dt>Knowledge source</dt><dd>KnowledgeItem #{finding.knowledge_source_id}</dd>")

    sections = [f"<p>{escape(finding.description)}</p>"]
    for label, value in (
        ("Evidence", finding.evidence),
        ("Reproduction", finding.reproduction_steps),
        ("Impact", finding.impact),
        ("Remediation", finding.remediation),
    ):
        if value:
            sections.append(f'<div class="section-title">{label}</div><pre>{escape(value)}</pre>')
    if finding.references:
        items = "".join(f"<li>{escape(reference)}</li>" for reference in finding.references)
        sections.append(f'<div class="section-title">References</div><ul>{items}</ul>')

    return (
        '<div class="finding">'
        f'<h2><span class="severity-badge" style="background:{color}">{escape(severity.upper())}</span>'
        f"{escape(finding.title)}</h2>"
        f"<dl>{''.join(rows)}</dl>"
        f"{''.join(sections)}"
        "</div>"
    )


class HTMLReportGenerator:
    format_name = "html"

    def generate(self, *, findings: list[Finding], output_path: Path) -> Path:
        ordered = sort_findings(findings)
        generated_at = datetime.now(timezone.utc).isoformat()
        body = "".join(_finding_html(finding) for finding in ordered) or "<p><em>No findings.</em></p>"

        document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HunterBot Vulnerability Report</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>HunterBot Vulnerability Report</h1>
<p class="meta">Generated: {escape(generated_at)} &middot; Total findings: {len(ordered)}</p>
{body}
</body>
</html>
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")
        return output_path
