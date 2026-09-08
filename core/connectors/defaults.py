from core.connectors.entra_id import EntraIdConnector
from core.connectors.linux_auth import LinuxAuthConnector
from core.connectors.registry import ConnectorRegistry
from core.connectors.suricata_eve import SuricataEveConnector
from core.connectors.syslog_rfc import SyslogRfcConnector
from core.connectors.sysmon import SysmonConnector
from core.connectors.windows_security import WindowsSecurityConnector
from core.connectors.zeek import ZeekConnector


def build_default_connector_registry() -> ConnectorRegistry:
    """Return the connectors enabled in the governed multi-source profile."""

    registry = ConnectorRegistry()
    registry.register(LinuxAuthConnector())
    registry.register(EntraIdConnector())
    registry.register(WindowsSecurityConnector())
    registry.register(SysmonConnector())
    registry.register(SyslogRfcConnector())
    registry.register(SuricataEveConnector())
    registry.register(ZeekConnector())
    return registry
