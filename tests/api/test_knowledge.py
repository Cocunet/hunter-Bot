class TestKnowledgeApi:
    def _ingest_headers_doc(self, client) -> None:
        client.post("/sources", json={"name": "Headers Guide", "source_type": "documentation"})
        content = (
            b"# Missing X-Frame-Options Header\n\n"
            b"## Summary\n\n"
            b"The X-Frame-Options HTTP header protects against clickjacking attacks. CWE-1021\n\n"
            b"## Remediation\n\n"
            b"Set the X-Frame-Options header to DENY or SAMEORIGIN.\n"
        )
        client.post(
            "/sources/Headers Guide/ingest",
            files={"file": ("headers.md", content, "text/markdown")},
        )

    def test_search_by_keyword(self, client) -> None:
        self._ingest_headers_doc(client)

        response = client.get("/knowledge/search", params={"keyword": "X-Frame-Options"})

        assert response.status_code == 200
        assert len(response.json()) >= 1

    def test_search_with_no_matches_returns_empty_list(self, client) -> None:
        response = client.get("/knowledge/search", params={"keyword": "nothing-matches-this"})

        assert response.status_code == 200
        assert response.json() == []

    def test_semantic_search_falls_back_gracefully_without_scikit_learn(self, client) -> None:
        self._ingest_headers_doc(client)

        response = client.get("/knowledge/semantic-search", params={"query": "clickjacking header"})

        assert response.status_code == 200
        body = response.json()
        assert "results" in body
        assert isinstance(body["used_semantic_backend"], bool)

    def test_history_for_unknown_item_returns_404(self, client) -> None:
        response = client.get("/knowledge/999/history")

        assert response.status_code == 404

    def test_history_for_known_item_with_no_revisions(self, client) -> None:
        self._ingest_headers_doc(client)
        item_id = client.get("/knowledge/search", params={"keyword": "X-Frame-Options"}).json()[0]["id"]

        response = client.get(f"/knowledge/{item_id}/history")

        assert response.status_code == 200
        body = response.json()
        assert body["current"]["id"] == item_id
        assert body["revisions"] == []
