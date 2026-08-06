from hunterbot.core.domain import Severity, Source, SourceType, VulnerabilityCategory
from hunterbot.knowledge.extraction import RuleBasedExtractor

_SOURCE = Source(id=1, name="Test Source", source_type=SourceType.DOCUMENTATION)


class TestRuleBasedExtractor:
    def test_extracts_sql_injection_paragraph_with_cwe_and_owasp(self) -> None:
        text = (
            "SQL Injection occurs when untrusted input is concatenated into a database "
            "query. This is CWE-89 and maps to A03:2021 Injection in the OWASP Top 10. "
            "It can be a critical vulnerability if left unpatched."
        )
        items = RuleBasedExtractor().extract(text=text, source=_SOURCE)

        assert len(items) == 1
        item = items[0]
        assert item.category == VulnerabilityCategory.INPUT_VALIDATION
        assert item.cwe == "CWE-89"
        assert item.owasp_category == "A03:2021"
        assert item.severity_hint == Severity.CRITICAL
        assert item.source_id == 1

    def test_skips_short_paragraphs(self) -> None:
        text = "SQL injection."
        assert RuleBasedExtractor().extract(text=text, source=_SOURCE) == []

    def test_skips_paragraphs_with_no_category_keywords(self) -> None:
        text = (
            "This paragraph is long enough to pass the minimum length check but has "
            "nothing at all to do with any known vulnerability category keywords."
        )
        assert RuleBasedExtractor().extract(text=text, source=_SOURCE) == []

    def test_deduplicates_identical_paragraphs_within_one_document(self) -> None:
        paragraph = (
            "Missing security headers such as Content-Security-Policy and "
            "X-Frame-Options can expose an application to clickjacking attacks."
        )
        text = f"{paragraph}\n\n{paragraph}"

        items = RuleBasedExtractor().extract(text=text, source=_SOURCE)

        assert len(items) == 1

    def test_requires_persisted_source(self) -> None:
        unpersisted_source = Source(name="No Id", source_type=SourceType.BLOG)
        try:
            RuleBasedExtractor().extract(text="anything", source=unpersisted_source)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for source without id")
