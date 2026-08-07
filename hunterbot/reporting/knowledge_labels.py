from hunterbot.core.domain import Finding


def knowledge_source_label(finding: Finding, knowledge_titles: dict[int, str] | None) -> str | None:
    """Human-readable label for a Finding's linked KnowledgeItem, if any.

    Falls back to a bare "KnowledgeItem #N" when the id has no resolved
    title in ``knowledge_titles`` (e.g. the caller didn't build the map, or
    the item no longer exists) — every generator renders the same shape.
    """
    if finding.knowledge_source_id is None:
        return None
    title = (knowledge_titles or {}).get(finding.knowledge_source_id)
    if title:
        return f"KnowledgeItem #{finding.knowledge_source_id} — {title}"
    return f"KnowledgeItem #{finding.knowledge_source_id}"
