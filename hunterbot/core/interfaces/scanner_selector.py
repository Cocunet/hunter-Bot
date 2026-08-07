from __future__ import annotations

from typing import Protocol

from hunterbot.core.interfaces.scanner import ScannerPlugin


class ScannerSelector(Protocol):
    """Chooses which already-registered scanners are worth running.

    Deliberately narrow: a selector picks names from ``available_scanners``
    — it never gets to invent a request or a target of its own. That keeps
    every scan within the same fixed, safety-reviewed set of read-only
    ScannerPlugins whether or not adaptive selection is used; the only
    thing adaptive selection can change is *which subset* of that
    already-vetted set runs, never what any of them do.

    ``recon_signal`` is a short, caller-built description of what an
    initial lightweight probe of the target revealed (status, headers, a
    body snippet) — the only per-target context a selector gets, not free
    rein to make its own requests.
    """

    def select(
        self, *, base_url: str, recon_signal: str, available_scanners: list[ScannerPlugin]
    ) -> list[str]: ...
