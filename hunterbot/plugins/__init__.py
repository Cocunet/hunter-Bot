from hunterbot.core.interfaces import ScannerPlugin
from hunterbot.plugins.directory_exposure.scanner import DirectoryListingExposureScanner
from hunterbot.plugins.exposure.scanner import SensitiveFileExposureScanner
from hunterbot.plugins.headers.scanner import MissingSecurityHeadersScanner
from hunterbot.plugins.info_disclosure.scanner import InformationDisclosureScanner
from hunterbot.scanners.registry import ScannerRegistry


def default_registry() -> ScannerRegistry:
    """The built-in set of scanner plugins, registered and ready to run."""
    registry = ScannerRegistry()
    registry.register(MissingSecurityHeadersScanner())
    registry.register(SensitiveFileExposureScanner())
    registry.register(DirectoryListingExposureScanner())
    registry.register(InformationDisclosureScanner())
    return registry


def default_scanners() -> list[ScannerPlugin]:
    return default_registry().all()


__all__ = [
    "DirectoryListingExposureScanner",
    "InformationDisclosureScanner",
    "MissingSecurityHeadersScanner",
    "SensitiveFileExposureScanner",
    "default_registry",
    "default_scanners",
]
