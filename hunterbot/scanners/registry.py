from hunterbot.core.interfaces import ScannerPlugin


class ScannerRegistry:
    """Holds the set of scanner plugins a scan run will execute.

    An explicit, instantiable registry (rather than a module-level global)
    so tests and callers can build an isolated set of plugins instead of
    sharing process-wide state.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"a scanner named {plugin.name!r} is already registered")
        self._plugins[plugin.name] = plugin

    def all(self) -> list[ScannerPlugin]:
        return list(self._plugins.values())
