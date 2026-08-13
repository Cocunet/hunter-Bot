class TestFindingsApi:
    def test_list_findings_empty_by_default(self, client) -> None:
        response = client.get("/findings")

        assert response.status_code == 200
        assert response.json() == []

    def test_list_findings_filtered_by_unknown_asset_is_empty(self, client) -> None:
        response = client.get("/findings", params={"asset": "https://nowhere.example.com"})

        assert response.status_code == 200
        assert response.json() == []
