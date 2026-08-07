class TestScansApi:
    def test_scan_unauthorized_target_returns_403(self, client, live_server: str) -> None:
        response = client.post("/scans", json={"base_url": live_server})

        assert response.status_code == 403

    def test_scan_authorized_target_finds_missing_headers(self, client, live_server: str) -> None:
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )

        response = client.post("/scans", json={"base_url": live_server})

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) > 0
        assert any(f["scanner_name"] == "missing-security-headers" for f in findings)

        listed = client.get("/findings").json()
        assert len(listed) == len(findings)

    def test_adaptive_scan_without_llm_credentials_falls_back_to_full_scan(
        self, client, live_server: str
    ) -> None:
        # No ANTHROPIC_API_KEY is configured in the test environment, so
        # LLMScannerSelector.select() fails -- RunScanUseCase's safe
        # fallback (run everything) means this must still succeed exactly
        # like a non-adaptive scan, never a 500 or a silently empty result.
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )

        response = client.post("/scans", json={"base_url": live_server, "adaptive": True})

        assert response.status_code == 200
        findings = response.json()
        assert len(findings) > 0
        assert any(f["scanner_name"] == "missing-security-headers" for f in findings)


class TestReportsApi:
    def test_generate_markdown_report_after_scan(self, client, live_server: str) -> None:
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )
        client.post("/scans", json={"base_url": live_server})

        response = client.post("/reports", json={"format": "markdown"})

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        assert b"HunterBot Vulnerability Report" in response.content

    def test_unsupported_format_returns_400(self, client) -> None:
        response = client.post("/reports", json={"format": "csv"})

        assert response.status_code == 400
