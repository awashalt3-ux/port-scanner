from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    scheme: str = "http"


@dataclass(frozen=True)
class ScanContext:
    timeout: float = 5.0
    dns_server: str | None = None


@dataclass
class ModuleResult:
    name: str
    ok: bool
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.name,
            "ok": self.ok,
            "summary": self.summary,
            "data": self.data,
            "error": self.error,
        }


class ScanModule(Protocol):
    name: str

    async def run(self, target: Target, context: ScanContext) -> ModuleResult: ...


def ascii_host(host: str) -> str:
    host = host.strip().rstrip(".")
    if not host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host
