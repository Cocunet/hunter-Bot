from hunterbot.plugins import default_scanners


class TestDefaultScanners:
    def test_registers_every_built_in_plugin_with_a_unique_name(self) -> None:
        scanners = default_scanners()

        names = [scanner.name for scanner in scanners]
        assert len(names) == len(set(names))
        assert set(names) == {
            "missing-security-headers",
            "sensitive-file-exposure",
            "directory-listing-exposure",
            "information-disclosure",
            "cookie-security",
            "cors-misconfiguration",
            "open-redirect",
            "http-method-tampering",
            "admin-interface-exposure",
        }
