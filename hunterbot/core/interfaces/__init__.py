from hunterbot.core.interfaces.authorization import AuthorizationChecker
from hunterbot.core.interfaces.correlation import KnowledgeCorrelator
from hunterbot.core.interfaces.extractor import KnowledgeExtractor
from hunterbot.core.interfaces.repositories import (
    FindingRepository,
    KnowledgeRepository,
    KnowledgeRevisionRepository,
    ScopeRepository,
    SourceRepository,
)
from hunterbot.core.interfaces.reporter import ReportGenerator
from hunterbot.core.interfaces.scanner import HttpClient, ScannerPlugin, ScannerResponse
from hunterbot.core.interfaces.semantic_index import SemanticIndex, SemanticMatch

__all__ = [
    "AuthorizationChecker",
    "FindingRepository",
    "HttpClient",
    "KnowledgeCorrelator",
    "KnowledgeExtractor",
    "KnowledgeRepository",
    "KnowledgeRevisionRepository",
    "ReportGenerator",
    "ScannerPlugin",
    "ScannerResponse",
    "ScopeRepository",
    "SemanticIndex",
    "SemanticMatch",
    "SourceRepository",
]
