import re

from hunterbot.core.domain import KnowledgeItem, Severity, Source, VulnerabilityCategory
from hunterbot.knowledge.extraction.hashing import content_hash

_MIN_PARAGRAPH_LENGTH = 40

# Keyword -> category signal. A paragraph is only extracted as knowledge if
# at least one keyword matches; the highest-scoring category wins. This is a
# deliberately simple heuristic — see hunterbot.core.interfaces.KnowledgeExtractor
# for the swap-in point for an LLM-backed extractor later.
_CATEGORY_KEYWORDS: dict[VulnerabilityCategory, tuple[str, ...]] = {
    VulnerabilityCategory.MISSING_SECURITY_HEADERS: (
        "security header",
        "content-security-policy",
        "x-frame-options",
        "strict-transport-security",
        "hsts",
        "x-content-type-options",
    ),
    VulnerabilityCategory.INPUT_VALIDATION: (
        "sql injection",
        "cross-site scripting",
        "xss",
        "input validation",
        "command injection",
        "xxe",
        "xml external entity",
    ),
    VulnerabilityCategory.AUTHORIZATION_ISSUE: (
        "broken access control",
        "privilege escalation",
        "idor",
        "insecure direct object reference",
        "authorization bypass",
    ),
    VulnerabilityCategory.AUTHENTICATION_WEAKNESS: (
        "weak password",
        "authentication bypass",
        "brute force",
        "session fixation",
        "credential stuffing",
    ),
    VulnerabilityCategory.API_SECURITY: (
        "api key",
        "rate limiting",
        "graphql",
        "rest api",
        "api endpoint",
    ),
    VulnerabilityCategory.SENSITIVE_FILE_EXPOSURE: (
        ".env",
        "sensitive file",
        "config file exposure",
        "credentials file",
        ".git/",
    ),
    VulnerabilityCategory.BACKUP_FILE_EXPOSURE: (
        "backup file",
        ".bak",
        ".old",
        ".swp",
        "database dump",
    ),
    VulnerabilityCategory.DIRECTORY_EXPOSURE: (
        "directory listing",
        "directory traversal",
        "path traversal",
        "../",
    ),
    VulnerabilityCategory.SECURITY_MISCONFIGURATION: (
        "misconfiguration",
        "default credentials",
        "debug mode",
        "verbose error",
        "stack trace",
    ),
    VulnerabilityCategory.INFORMATION_DISCLOSURE: (
        "information disclosure",
        "sensitive data exposure",
        "data leak",
    ),
    VulnerabilityCategory.CONFIGURATION_ISSUE: (
        "insecure configuration",
        "default settings",
        "misconfigured",
    ),
}

_SEVERITY_KEYWORDS: tuple[tuple[Severity, tuple[str, ...]], ...] = (
    (Severity.CRITICAL, ("critical severity", "critical vulnerability", "remote code execution")),
    (Severity.HIGH, ("high severity", "high risk")),
    (Severity.MEDIUM, ("medium severity", "moderate risk")),
    (Severity.LOW, ("low severity", "low risk", "informational")),
)

_OWASP_CATEGORIES = (
    "Broken Access Control",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Security Misconfiguration",
    "Vulnerable and Outdated Components",
    "Identification and Authentication Failures",
    "Software and Data Integrity Failures",
    "Security Logging and Monitoring Failures",
    "Server-Side Request Forgery",
)

_CWE_PATTERN = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)
_OWASP_CODE_PATTERN = re.compile(r"\bA\d{1,2}:20\d{2}\b")
_TITLE_MAX_LENGTH = 120


def _score_category(lowered_paragraph: str) -> tuple[VulnerabilityCategory, tuple[str, ...]] | None:
    best_category: VulnerabilityCategory | None = None
    best_matches: tuple[str, ...] = ()
    best_score = 0
    for category, keywords in _CATEGORY_KEYWORDS.items():
        matches = tuple(keyword for keyword in keywords if keyword in lowered_paragraph)
        if len(matches) > best_score:
            best_score = len(matches)
            best_category = category
            best_matches = matches
    if best_category is None:
        return None
    return best_category, best_matches


def _find_cwe(paragraph: str) -> str | None:
    match = _CWE_PATTERN.search(paragraph)
    return match.group(0).upper() if match else None


def _find_owasp_category(paragraph: str) -> str | None:
    code_match = _OWASP_CODE_PATTERN.search(paragraph)
    if code_match:
        return code_match.group(0)
    lowered = paragraph.lower()
    for category in _OWASP_CATEGORIES:
        if category.lower() in lowered:
            return category
    return None


def _find_severity(lowered_paragraph: str) -> Severity | None:
    for severity, keywords in _SEVERITY_KEYWORDS:
        if any(keyword in lowered_paragraph for keyword in keywords):
            return severity
    return None


def _derive_title(paragraph: str) -> str:
    first_line = paragraph.strip().splitlines()[0]
    if len(first_line) > _TITLE_MAX_LENGTH:
        return first_line[: _TITLE_MAX_LENGTH - 3].rstrip() + "..."
    return first_line


class RuleBasedExtractor:
    """Deterministic, keyword-driven KnowledgeExtractor implementation.

    Splits normalized text into paragraph-sized chunks and keeps only the
    ones that match a known vulnerability-category keyword set, tagging each
    with any CWE id, OWASP category, and severity hint found in the text.
    This is intentionally simple and fully auditable; it satisfies the
    KnowledgeExtractor interface so a future LLM-backed extractor can be
    swapped in without touching the ingestion pipeline.
    """

    def extract(self, *, text: str, source: Source) -> list[KnowledgeItem]:
        if source.id is None:
            raise ValueError("source must be persisted (have an id) before extraction")

        items: list[KnowledgeItem] = []
        seen_hashes: set[str] = set()
        for paragraph in text.split("\n\n"):
            paragraph = paragraph.strip()
            if len(paragraph) < _MIN_PARAGRAPH_LENGTH:
                continue

            lowered = paragraph.lower()
            scored = _score_category(lowered)
            if scored is None:
                continue
            category, matched_keywords = scored

            paragraph_hash = content_hash(paragraph)
            if paragraph_hash in seen_hashes:
                continue
            seen_hashes.add(paragraph_hash)

            items.append(
                KnowledgeItem(
                    source_id=source.id,
                    category=category,
                    title=_derive_title(paragraph),
                    summary=paragraph,
                    content_hash=paragraph_hash,
                    cwe=_find_cwe(paragraph),
                    owasp_category=_find_owasp_category(paragraph),
                    severity_hint=_find_severity(lowered),
                    tags=tuple(sorted(set(matched_keywords))),
                )
            )
        return items
