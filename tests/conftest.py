import pytest
from sqlalchemy.orm import Session

from hunterbot.core.interfaces import ScannerResponse
from hunterbot.storage.database import create_engine_from_url, get_session_factory, init_db


@pytest.fixture
def session() -> Session:
    engine = create_engine_from_url("sqlite:///:memory:")
    init_db(engine)
    session_factory = get_session_factory(engine)
    with session_factory() as db_session:
        yield db_session


class FakeHttpClient:
    """Test double satisfying hunterbot.core.interfaces.HttpClient.

    Responses are keyed by path; a path with no configured response yields
    None, matching how ScannerHttpClient treats network failures.
    ``options_responses`` is a separate mapping (defaulting to ``responses``
    itself) since a real server's OPTIONS response at a path is typically
    quite different from its GET response there.
    """

    def __init__(
        self,
        responses: dict[str, ScannerResponse] | None = None,
        options_responses: dict[str, ScannerResponse] | None = None,
    ) -> None:
        self._responses = responses or {}
        self._options_responses = self._responses if options_responses is None else options_responses
        self.requested_paths: list[str] = []
        self.closed = False

    def get(self, path: str) -> ScannerResponse | None:
        self.requested_paths.append(path)
        return self._responses.get(path)

    def get_no_redirect(self, path: str) -> ScannerResponse | None:
        self.requested_paths.append(path)
        return self._responses.get(path)

    def options(self, path: str) -> ScannerResponse | None:
        self.requested_paths.append(path)
        return self._options_responses.get(path)

    def close(self) -> None:
        self.closed = True
