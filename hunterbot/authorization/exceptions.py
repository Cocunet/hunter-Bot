class NotAuthorizedError(Exception):
    """Raised when a target has no matching, currently-active Scope.

    Every scanning use-case must let this propagate rather than catch and
    continue — there is no "scan anyway" path in this codebase.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        super().__init__(f"{target!r} is not covered by any active authorization scope")
