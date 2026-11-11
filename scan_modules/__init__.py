from __future__ import annotations

from .base import ModuleResult, ScanContext, ScanModule, Target
from .dns_scan import DnsScanModule
from .robots_txt import RobotsTxtModule

MODULES: dict[str, ScanModule] = {
    "dns": DnsScanModule(),
    "robots": RobotsTxtModule(),
}

__all__ = [
    "MODULES",
    "DnsScanModule",
    "ModuleResult",
    "RobotsTxtModule",
    "ScanContext",
    "ScanModule",
    "Target",
]
