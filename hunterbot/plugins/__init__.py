from hunterbot.core.interfaces import ScannerPlugin
from hunterbot.plugins.admin_interface_exposure.scanner import AdminInterfaceExposureScanner
from hunterbot.plugins.cookie_security.scanner import CookieSecurityScanner
from hunterbot.plugins.cors_misconfiguration.scanner import CorsMisconfigurationScanner
from hunterbot.plugins.directory_exposure.scanner import DirectoryListingExposureScanner
from hunterbot.plugins.exposure.scanner import SensitiveFileExposureScanner
from hunterbot.plugins.headers.scanner import MissingSecurityHeadersScanner
from hunterbot.plugins.http_methods.scanner import HttpMethodTamperingScanner
from hunterbot.plugins.info_disclosure.scanner import InformationDisclosureScanner
from hunterbot.plugins.open_redirect.scanner import OpenRedirectScanner
from hunterbot.plugins.reflected_xss.scanner import ReflectedXssScanner
from hunterbot.plugins.sql_injection.scanner import SqlInjectionScanner
from hunterbot.plugins.ssrf.scanner import SsrfScanner
from hunterbot.scanners.registry import ScannerRegistry


def default_registry() -> ScannerRegistry:
    """The built-in set of scanner plugins, registered and ready to run."""
    registry = ScannerRegistry()
    registry.register(MissingSecurityHeadersScanner())
    registry.register(SensitiveFileExposureScanner())
    registry.register(DirectoryListingExposureScanner())
    registry.register(InformationDisclosureScanner())
    registry.register(CookieSecurityScanner())
    registry.register(CorsMisconfigurationScanner())
    registry.register(OpenRedirectScanner())
    registry.register(HttpMethodTamperingScanner())
    registry.register(AdminInterfaceExposureScanner())
    registry.register(ReflectedXssScanner())
    registry.register(SqlInjectionScanner())
    registry.register(SsrfScanner())
    return registry


def default_scanners() -> list[ScannerPlugin]:
    return default_registry().all()


__all__ = [
    "AdminInterfaceExposureScanner",
    "CookieSecurityScanner",
    "CorsMisconfigurationScanner",
    "DirectoryListingExposureScanner",
    "HttpMethodTamperingScanner",
    "InformationDisclosureScanner",
    "MissingSecurityHeadersScanner",
    "OpenRedirectScanner",
    "ReflectedXssScanner",
    "SensitiveFileExposureScanner",
    "SqlInjectionScanner",
    "SsrfScanner",
    "default_registry",
    "default_scanners",
]
