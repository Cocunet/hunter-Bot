class TestFindingsAnalyzeApi:
    def test_analyze_with_no_findings_short_circuits_without_a_real_api_call(self, client) -> None:
        # LLMFindingAnalyzer.analyze short-circuits on an empty findings list
        # before ever calling the Claude API, so this must succeed even with
        # no ANTHROPIC_API_KEY configured (as in the test environment).
        response = client.post("/findings/analyze", json={})

        assert response.status_code == 200
        body = response.json()
        assert body["summary"] == "No findings to analyze."
        assert body["triage"] == []
        assert body["attack_chains"] == []

    def test_analyze_with_findings_but_no_llm_credentials_returns_400(self, client, live_server: str) -> None:
        # No ANTHROPIC_API_KEY is configured in the test environment, so
        # once there's at least one real finding to analyze (past the
        # empty-list short circuit), the actual Claude API call fails and
        # the route must surface that as a clean 400, not a 500.
        client.post(
            "/scopes",
            json={"target": "127.0.0.1", "program_name": "Local", "authorized_by": "Tester"},
        )
        scan_response = client.post("/scans", json={"base_url": live_server})
        assert len(scan_response.json()) > 0

        response = client.post("/findings/analyze", json={})

        assert response.status_code == 400
