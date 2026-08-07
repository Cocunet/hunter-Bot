import hashlib


def content_hash(text: str) -> str:
    """Stable sha256 hex digest of normalized text.

    This is the identity/dedupe key hunterbot.learning.KnowledgeDiffEngine
    matches on, so every KnowledgeExtractor implementation (rule-based,
    LLM-backed, ...) must normalize the same way: case-folded, whitespace-
    collapsed. Two extractors given the same underlying text should produce
    the same hash even if their surrounding summary formatting differs
    slightly, as long as they hash the same normalized span.
    """
    normalized = " ".join(text.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
