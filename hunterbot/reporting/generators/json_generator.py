import json
from datetime import datetime, timezone
from pathlib import Path

from hunterbot.core.domain import Finding
from hunterbot.reporting.ordering import sort_findings


class JSONReportGenerator:
    format_name = "json"

    def generate(self, *, findings: list[Finding], output_path: Path) -> Path:
        ordered = sort_findings(findings)
        document = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(ordered),
            "findings": [finding.model_dump(mode="json") for finding in ordered],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return output_path
