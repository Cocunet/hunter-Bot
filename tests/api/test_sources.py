class TestSourcesApi:
    def test_create_and_list_source(self, client) -> None:
        response = client.post("/sources", json={"name": "OWASP Top 10", "source_type": "documentation"})
        assert response.status_code == 201
        body = response.json()
        assert body["name"] == "OWASP Top 10"

        listed = client.get("/sources").json()
        assert len(listed) == 1

    def test_duplicate_name_returns_409(self, client) -> None:
        client.post("/sources", json={"name": "OWASP Top 10", "source_type": "documentation"})

        response = client.post("/sources", json={"name": "OWASP Top 10", "source_type": "documentation"})

        assert response.status_code == 409

    def test_ingest_unknown_source_returns_404(self, client) -> None:
        response = client.post(
            "/sources/Nonexistent/ingest",
            files={"file": ("notes.md", b"# Title\n\nSome content.", "text/markdown")},
        )

        assert response.status_code == 404

    def test_ingest_document_extracts_knowledge(self, client) -> None:
        client.post("/sources", json={"name": "Headers Guide", "source_type": "documentation"})

        content = (
            b"# Missing X-Frame-Options Header\n\n"
            b"## Summary\n\n"
            b"The X-Frame-Options HTTP header protects against clickjacking attacks. "
            b"CWE-1021\n\n"
            b"## Remediation\n\n"
            b"Set the X-Frame-Options header to DENY or SAMEORIGIN.\n"
        )
        response = client.post(
            "/sources/Headers Guide/ingest",
            files={"file": ("headers.md", content, "text/markdown")},
            data={"extractor": "rule-based"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["items_extracted"] >= 1
        assert body["items_added"] >= 1

        found = client.get("/knowledge/search", params={"keyword": "X-Frame-Options"}).json()
        assert len(found) >= 1

    def test_ingest_unsupported_extension_returns_400(self, client) -> None:
        client.post("/sources", json={"name": "Weird Source", "source_type": "other"})

        response = client.post(
            "/sources/Weird Source/ingest",
            files={"file": ("notes.txt", b"plain text", "text/plain")},
        )

        assert response.status_code == 400
