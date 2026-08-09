from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from hunterbot.core.domain import AuthSession, Scope, ScopeStatus, target_matches


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

    def test_naive_expires_at_is_normalized_to_utc_not_rejected(self) -> None:
        # A naive datetime here (e.g. from Typer's date-only --expires-at,
        # or an API request body without a timezone suffix) must not raise
        # TypeError comparing it against the aware authorized_at, and must
        # not fail later at the storage layer (UTCDateTime requires
        # timezone-aware values) -- regression test for a real bug found
        # via manual CLI testing.
        naive_future = datetime.now() + timedelta(days=365)  # deliberately naive
        scope = Scope(target="example.com", program_name="Acme", authorized_by="Alice", expires_at=naive_future)

        assert scope.expires_at.tzinfo is not None
        assert scope.is_currently_active() is True

    def test_naive_authorized_at_is_normalized_to_utc(self) -> None:
        naive_past = datetime.now() - timedelta(days=1)  # deliberately naive
        scope = Scope(target="example.com", program_name="Acme", authorized_by="Alice", authorized_at=naive_past)

        assert scope.authorized_at.tzinfo is not None


class TestAuthSession:
    def test_no_expiry_is_active(self) -> None:
        session = AuthSession(scope_id=1, name="admin", headers={"Cookie": "session=abc"})
        assert session.is_currently_active() is True

    def test_future_expiry_is_active(self) -> None:
        now = datetime.now(timezone.utc)
        session = AuthSession(
            scope_id=1, name="admin", headers={"Cookie": "session=abc"}, expires_at=now + timedelta(days=1)
        )
        assert session.is_currently_active(now=now) is True

    def test_past_expiry_is_not_active(self) -> None:
        now = datetime.now(timezone.utc)
        session = AuthSession(
            scope_id=1, name="admin", headers={"Cookie": "session=abc"}, expires_at=now - timedelta(days=1)
        )
        assert session.is_currently_active(now=now) is False

    def test_empty_headers_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuthSession(scope_id=1, name="admin", headers={})

    def test_naive_expires_at_is_normalized_to_utc(self) -> None:
        naive_future = datetime.now() + timedelta(days=365)  # deliberately naive
        session = AuthSession(
            scope_id=1, name="admin", headers={"Cookie": "session=abc"}, expires_at=naive_future
        )

        assert session.expires_at.tzinfo is not None
        assert session.is_currently_active() is True

    def test_masked_headers_hides_values_but_keeps_names(self) -> None:
        session = AuthSession(
            scope_id=1,
            name="admin",
            headers={"Cookie": "session=super-secret-value", "X-Api-Key": "another-secret"},
        )

        masked = session.masked_headers()

        assert set(masked.keys()) == {"Cookie", "X-Api-Key"}
        assert "super-secret-value" not in masked.values()
        assert "another-secret" not in masked.values()


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
