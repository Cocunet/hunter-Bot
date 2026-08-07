import json
from pathlib import Path

import pytest

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.reporting import HTMLReportGenerator, JSONReportGenerator, MarkdownReportGenerator, get_generator
from hunterbot.reporting.ordering import sort_findings


def _finding(title: str, severity: Severity, **overrides) -> Finding:
    defaults = dict(
        title=title,
        category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        severity=severity,
        confidence=Confidence.HIGH,
        description="A test finding description.",
        affected_asset="https://example.com",
        location="https://example.com/",
        scanner_name="test-scanner",
    )
    defaults.update(overrides)
    return Finding(**defaults)


_LOW = _finding("Low severity issue", Severity.LOW)
_CRITICAL = _finding(
    "Critical severity issue",
    Severity.CRITICAL,
    evidence="raw evidence",
    reproduction_steps="1. Do X\n2. Do Y",
    impact="Full compromise.",
    remediation="Patch it.",
    references=("https://example.com/advisory",),
    knowledge_source_id=7,
)


class TestSortFindings:
    def test_orders_most_severe_first(self) -> None:
        ordered = sort_findings([_LOW, _CRITICAL])
        assert [f.title for f in ordered] == ["Critical severity issue", "Low severity issue"]


class TestMarkdownReportGenerator:
    def test_generate_writes_file_with_all_sections(self, tmp_path: Path) -> None:
        output_path = tmp_path / "report.md"

        result = MarkdownReportGenerator().generate(findings=[_CRITICAL, _LOW], output_path=output_path)

        assert result == output_path
        content = output_path.read_text(encoding="utf-8")
        assert "# HunterBot Vulnerability Report" in content
        assert "Total findings: 2" in content
        assert "[CRITICAL] Critical severity issue" in content
        assert "raw evidence" in content
        assert "Patch it." in content
        assert "https://example.com/advisory" in content
        # Critical should appear before Low in the rendered output.
        assert content.index("Critical severity issue") < content.index("Low severity issue")

    def test_generate_with_no_findings(self, tmp_path: Path) -> None:
        output_path = tmp_path / "empty.md"
        MarkdownReportGenerator().generate(findings=[], output_path=output_path)
        assert "No findings" in output_path.read_text(encoding="utf-8")

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        output_path = tmp_path / "nested" / "dir" / "report.md"
        MarkdownReportGenerator().generate(findings=[], output_path=output_path)
        assert output_path.exists()


class TestJSONReportGenerator:
    def test_generate_produces_valid_json_with_all_findings(self, tmp_path: Path) -> None:
        output_path = tmp_path / "report.json"

        JSONReportGenerator().generate(findings=[_CRITICAL, _LOW], output_path=output_path)

        document = json.loads(output_path.read_text(encoding="utf-8"))
        assert document["total_findings"] == 2
        assert document["findings"][0]["title"] == "Critical severity issue"
        assert document["findings"][0]["references"] == ["https://example.com/advisory"]
        assert document["findings"][0]["knowledge_source_id"] == 7


class TestHTMLReportGenerator:
    def test_generate_escapes_and_includes_all_findings(self, tmp_path: Path) -> None:
        output_path = tmp_path / "report.html"
        malicious = _finding("<script>alert(1)</script>", Severity.HIGH)

        HTMLReportGenerator().generate(findings=[_CRITICAL, malicious], output_path=output_path)

        content = output_path.read_text(encoding="utf-8")
        assert "<!doctype html>" in content
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content
        assert "Critical severity issue" in content


class TestGetGenerator:
    def test_returns_matching_generator(self) -> None:
        assert isinstance(get_generator("markdown"), MarkdownReportGenerator)
        assert isinstance(get_generator("json"), JSONReportGenerator)
        assert isinstance(get_generator("html"), HTMLReportGenerator)

    def test_unsupported_format_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported report format"):
            get_generator("pdf")
