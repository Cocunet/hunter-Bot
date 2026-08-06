from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from hunterbot.core.domain import Scope, ScopeStatus, target_matches


class TestScope:
    def test_active_scope_with_no_expiry_is_active(self) -> None:
        scope = Scope(target="example.com", program_name="Acme", authorized_by="Alice")
        assert scope.is_currently_active() is True

    def test_revoked_scope_is_not_active(self) -> None:
        scope = Scope(
            target="example.com",
            program_name="Acme",
            authorized_by="Alice",
            status=ScopeStatus.REVOKED,
        )
        assert scope.is_currently_active() is False

    def test_expired_scope_is_not_active(self) -> None:
        now = datetime.now(timezone.utc)
        scope = Scope(
            target="example.com",
            program_name="Acme",
            authorized_by="Alice",
            authorized_at=now - timedelta(days=2),
            expires_at=now - timedelta(days=1),
        )
        assert scope.is_currently_active(now=now) is False

    def test_future_expiry_is_active(self) -> None:
        now = datetime.now(timezone.utc)
        scope = Scope(
            target="example.com",
            program_name="Acme",
            authorized_by="Alice",
            expires_at=now + timedelta(days=1),
        )
        assert scope.is_currently_active(now=now) is True

    def test_expires_before_authorized_is_rejected(self) -> None:
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            Scope(
                target="example.com",
                program_name="Acme",
                authorized_by="Alice",
                authorized_at=now,
                expires_at=now - timedelta(days=1),
            )


class TestTargetMatches:
    def test_exact_match(self) -> None:
        assert target_matches("example.com", "example.com") is True

    def test_case_insensitive(self) -> None:
        assert target_matches("Example.COM", "example.com") is True

    def test_subdomain_matches_parent_domain(self) -> None:
        assert target_matches("example.com", "api.example.com") is True

    def test_unrelated_domain_does_not_match(self) -> None:
        assert target_matches("example.com", "example.net") is False

    def test_suffix_lookalike_does_not_match(self) -> None:
        assert target_matches("example.com", "notexample.com") is False

    def test_cidr_contains_address(self) -> None:
        assert target_matches("10.0.0.0/24", "10.0.0.42") is True

    def test_cidr_excludes_out_of_range_address(self) -> None:
        assert target_matches("10.0.0.0/24", "10.0.1.42") is False

    def test_single_ip_matches_itself(self) -> None:
        assert target_matches("203.0.113.5", "203.0.113.5") is True

    def test_hostname_vs_ip_does_not_crash(self) -> None:
        assert target_matches("example.com", "203.0.113.5") is False
