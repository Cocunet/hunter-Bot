from hunterbot.core.interfaces import ScannerPlugin
from hunterbot.plugins.exposure.scanner import SensitiveFileExposureScanner
from hunterbot.plugins.headers.scanner import MissingSecurityHeadersScanner
from hunterbot.scanners.registry import ScannerRegistry


def default_registry() -> ScannerRegistry:
    """The built-in set of scanner plugins, registered and ready to run."""
    registry = ScannerRegistry()
    registry.register(MissingSecurityHeadersScanner())
    registry.register(SensitiveFileExposureScanner())
    return registry


def default_scanners() -> list[ScannerPlugin]:
    return default_registry().all()


__all__ = [
    "MissingSecurityHeadersScanner",
    "SensitiveFileExposureScanner",
    "default_registry",
    "default_scanners",
]
