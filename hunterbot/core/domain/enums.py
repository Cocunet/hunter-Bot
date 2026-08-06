from enum import Enum


class SourceType(str, Enum):
    """Kind of educational resource an ingestion connector pulled from."""

    DOCUMENTATION = "documentation"
    VENDOR_DOC = "vendor_doc"
    WRITEUP = "writeup"
    CTF_WRITEUP = "ctf_writeup"
    BLOG = "blog"
    PAPER = "paper"
    GITHUB_REPO = "github_repo"
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    OTHER = "other"


class VulnerabilityCategory(str, Enum):
    """Coarse-grained category used to route knowledge items to scanners."""

    INFORMATION_DISCLOSURE = "information_disclosure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    MISSING_SECURITY_HEADERS = "missing_security_headers"
    DIRECTORY_EXPOSURE = "directory_exposure"
    BACKUP_FILE_EXPOSURE = "backup_file_exposure"
    SENSITIVE_FILE_EXPOSURE = "sensitive_file_exposure"
    API_SECURITY = "api_security"
    AUTHENTICATION_WEAKNESS = "authentication_weakness"
    AUTHORIZATION_ISSUE = "authorization_issue"
    INPUT_VALIDATION = "input_validation"
    CONFIGURATION_ISSUE = "configuration_issue"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ScopeStatus(str, Enum):
    """Authorization state of a registered scan target."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
