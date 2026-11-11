#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scan_modules import MODULES, ModuleResult, ScanContext, Target
from scan_modules.dns_scan import parse_dns_server

__version__ = "1.1.0"


def _configure_stdio() -> None:
    # Banners and headers routinely contain non-ASCII bytes; a cp1252 console
    # would raise UnicodeEncodeError and abort the whole report.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


_configure_stdio()

console = Console()
error_console = Console(stderr=True)

# Common service names, used to label open ports in the output.
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS",
    995: "POP3S", 1433: "MS SQL", 1521: "Oracle", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker TLS", 3000: "HTTP Alt", 3306: "MySQL",
    3389: "RDP", 5000: "HTTP Alt", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "AMQP", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    8000: "HTTP Alt", 8080: "HTTP Alt", 8081: "HTTP Alt", 8443: "HTTPS Alt",
    8888: "HTTP Alt", 9000: "HTTP Alt", 9090: "HTTP Alt", 9092: "Kafka",
    9200: "Elasticsearch", 9443: "HTTPS Alt", 10250: "Kubelet",
    11211: "Memcached", 15672: "RabbitMQ Mgmt", 27017: "MongoDB",
}

# Ports we probe with an HTTP request; other ports get a banner read first and
# are retried with an HTTP request when they stay silent (M1).
HTTP_PORTS: frozenset[int] = frozenset(
    {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9090}
)
TLS_PORTS: frozenset[int] = frozenset({443, 8443, 9443})

PROBE_CONCURRENCY = 100
SCAN_CONCURRENCY = 256
BANNER_IDLE_TIMEOUT = 0.2
MAX_BANNER_BYTES = 1024
MAX_HEADER_BYTES = 1 << 20  # 1 MiB: tolerate very large header blocks (H2)
MAX_HEADER_LINES = 12
MAX_HEADER_VALUE = 120
MAX_BANNER_TEXT = 200
CONNECT_LIMIT = 1 << 20


@dataclass
class ProbeResult:
    # What we found on one open port: a banner, HTTP headers, or an error.
    port: int
    banner: str = ""
    http_status: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "banner": self.banner or None,
            "http_status": self.http_status or None,
            # Keep repeated headers (Set-Cookie, WWW-Authenticate, Link, ...).
            "headers": [
                {"name": name, "value": value} for name, value in self.headers
            ],
            "error": self.error or None,
        }


def clean_text(data: bytes, limit: int = MAX_BANNER_TEXT) -> str:
    # Banners can contain control characters; keep them printable and short.
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def truncate_header(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > MAX_HEADER_VALUE:
        value = value[: MAX_HEADER_VALUE - 1] + "…"
    return value


def to_ascii_host(host: str) -> str:
    # IDNA-encode internationalised hostnames for DNS, SNI and the Host header.
    host = host.strip().rstrip(".")
    if not host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


_TLS_CONTEXT: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    # Build once and reuse: a scan can open hundreds of TLS connections (L1).
    global _TLS_CONTEXT
    if _TLS_CONTEXT is None:
        # Skip certificate checks: self-signed and internal hosts are common targets.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _TLS_CONTEXT = ctx
    return _TLS_CONTEXT


async def open_stream(
    connect_host: str,
    port: int,
    use_tls: bool,
    timeout: float,
    sni_host: str = "",
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    # Connect by IP, but keep the hostname for TLS SNI (C2).
    kwargs: dict[str, object] = {"limit": CONNECT_LIMIT}
    if use_tls:
        kwargs["ssl"] = tls_context()
        if sni_host:
            kwargs["server_hostname"] = sni_host
    return await asyncio.wait_for(
        asyncio.open_connection(connect_host, port, **kwargs), timeout=timeout
    )


async def resolve_hosts(host: str) -> list[str]:
    # Resolve once per scan so every port connection does not hit DNS again.
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    ascii_host = to_ascii_host(host)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(ascii_host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return [host]

    seen: set[str] = set()
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        addr = sockaddr[0] if sockaddr else ""
        if addr and addr not in seen:
            seen.add(addr)
            addresses.append(addr)
    return addresses or [ascii_host]


async def close_stream(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        # Never let cleanup errors mask the scan result (L6, M5). CancelledError
        # derives from BaseException, so cancellation still propagates.
        pass


async def read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    # Read until the server goes quiet. Silent ports must not block the scan.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    chunks = bytearray()

    while len(chunks) < MAX_BANNER_BYTES:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            # Read in chunks rather than one byte per wait_for call (L2).
            chunk = await asyncio.wait_for(
                reader.read(256), timeout=min(BANNER_IDLE_TIMEOUT, remaining)
            )
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        chunks.extend(chunk)

    return clean_text(bytes(chunks))


def parse_http_response(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
    # Pull out the status line and headers, ignoring any body bytes.
    if not raw:
        return "", []

    text = raw.decode("iso-8859-1", errors="replace")
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    lines = head.splitlines()
    if not lines:
        return "", []

    status = lines[0].strip()
    if not status.upper().startswith("HTTP/"):
        return "", []

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), truncate_header(value)))
    return status, headers


async def read_http_head(reader: asyncio.StreamReader, timeout: float) -> bytes:
    # Stop at the first blank line, accepting both CRLF and LF line endings (H1).
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    buf = bytearray()

    while len(buf) < MAX_HEADER_BYTES:
        if buf.find(b"\r\n\r\n") != -1 or buf.find(b"\n\n") != -1:
            break
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)

    crlf = buf.find(b"\r\n\r\n")
    lf = buf.find(b"\n\n")
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return bytes(buf[: crlf + 4])
    if lf != -1:
        return bytes(buf[: lf + 2])
    return bytes(buf)


def build_http_request(host: str, port: int) -> str:
    # Minimal request; we only care about the response headers.
    ascii_host = to_ascii_host(host)
    host_header = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port not in (80, 443):
        host_header += f":{port}"
    return (
        "GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: scanner.py/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )


async def probe_http(
    connect_host: str, host: str, port: int, use_tls: bool, timeout: float
) -> ProbeResult:
    try:
        reader, writer = await open_stream(
            connect_host, port, use_tls, timeout, sni_host=to_ascii_host(host)
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return ProbeResult(port=port, error=type(exc).__name__)

    try:
        writer.write(build_http_request(host, port).encode("ascii"))
        await writer.drain()
        raw = await read_http_head(reader, timeout)
        status, headers = parse_http_response(raw)
        if status:
            return ProbeResult(port=port, http_status=status, headers=headers)
        return ProbeResult(port=port, banner=clean_text(raw))
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return ProbeResult(port=port, error=type(exc).__name__)
    except UnicodeError as exc:
        # IDN or other host encoding failure must not abort the batch (H7, M5).
        return ProbeResult(port=port, error=type(exc).__name__)
    finally:
        await close_stream(writer)


async def grab_banner(
    connect_host: str, host: str, port: int, timeout: float
) -> ProbeResult:
    use_tls = port in TLS_PORTS
    try:
        reader, writer = await open_stream(
            connect_host, port, use_tls, timeout, sni_host=to_ascii_host(host)
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return ProbeResult(port=port, error=type(exc).__name__)

    try:
        return ProbeResult(port=port, banner=await read_banner(reader, timeout))
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return ProbeResult(port=port, error=type(exc).__name__)
    finally:
        await close_stream(writer)


async def probe_port(
    connect_host: str, host: str, port: int, timeout: float
) -> ProbeResult:
    # HTTP ports expect a request first; other ports may send a banner.
    if port in HTTP_PORTS:
        return await probe_http(connect_host, host, port, port in TLS_PORTS, timeout)

    result = await grab_banner(connect_host, host, port, timeout)
    if result.banner.upper().startswith("HTTP/"):
        return await probe_http(connect_host, host, port, port in TLS_PORTS, timeout)
    if not result.banner and not result.error:
        # A silent server may be waiting for a request rather than sending a
        # banner; retry with HTTP so non-standard HTTP ports are detected (M1).
        http_result = await probe_http(
            connect_host, host, port, port in TLS_PORTS, timeout
        )
        if http_result.http_status or http_result.banner or http_result.error:
            return http_result
    return result


async def probe_ports(
    host: str, open_ports: dict[int, str], timeout: float
) -> dict[int, ProbeResult]:
    # Probe each port on the address that answered the scan.
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def bounded(port: int, connect_host: str) -> tuple[int, ProbeResult]:
        async with sem:
            try:
                return port, await probe_port(connect_host, host, port, timeout)
            except Exception as exc:  # one bad probe must not kill the batch (M5)
                return port, ProbeResult(
                    port=port, error=f"{type(exc).__name__}: {exc}"
                )

    results = await asyncio.gather(
        *(bounded(port, addr) for port, addr in open_ports.items())
    )
    return dict(results)


async def probe_all(
    connect_host: str, host: str, ports: list[int], timeout: float
) -> dict[int, ProbeResult]:
    return await probe_ports(host, {port: connect_host for port in ports}, timeout)


async def run_modules(
    host: str,
    port: int,
    scheme: str,
    names: list[str],
    timeout: float,
    dns_server: str | None,
) -> list[ModuleResult]:
    target = Target(host=host, port=port, scheme=scheme)
    context = ScanContext(timeout=timeout, dns_server=dns_server)
    sem = asyncio.Semaphore(10)

    async def run(name: str) -> ModuleResult:
        async with sem:
            try:
                return await MODULES[name].run(target, context)
            except Exception as exc:  # one bad module must not kill the report
                return ModuleResult(
                    name=name,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                )

    results = await asyncio.gather(*(run(name) for name in names))
    return list(results)


def parse_module_names(spec: str) -> list[str]:
    names = [part.strip().lower() for part in spec.split(",") if part.strip()]
    if not names:
        raise ValueError("no modules specified")

    unknown = [name for name in names if name not in MODULES]
    if unknown:
        available = ", ".join(sorted(MODULES))
        raise ValueError(f"unknown module(s): {', '.join(unknown)} (available: {available})")

    return list(dict.fromkeys(names))


def _status_style(status: str) -> str:
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status)
    code = int(match.group(1)) if match else 0
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "bold cyan"
    return "bold red"


def format_probe(result: ProbeResult) -> Text:
    if result.error:
        return Text(result.error, style="red")

    lines: list[Text] = []
    if result.http_status:
        lines.append(
            Text.assemble(
                ("HTTP  ", "bold"),
                (result.http_status, _status_style(result.http_status)),
            )
        )
        for name, value in result.headers[:MAX_HEADER_LINES]:
            lines.append(Text.assemble((f"{name}: ", "cyan"), (value, "")))
        extra = len(result.headers) - MAX_HEADER_LINES
        if extra > 0:
            lines.append(Text(f"(+{extra} more headers)", style="dim"))
    elif result.banner:
        lines.append(Text.assemble(("banner  ", "bold"), (result.banner, "")))
    else:
        lines.append(Text("(no banner)", style="dim"))

    return Text("\n").join(lines)


def print_details(results: dict[int, ProbeResult]) -> None:
    if not results:
        return

    table = Table(box=None, padding=(0, 2), show_header=True, header_style="bold")
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("Service", style="white")
    table.add_column("Details", overflow="fold")

    for port in sorted(results):
        result = results[port]
        table.add_row(
            str(port),
            COMMON_PORTS.get(port, "unknown"),
            format_probe(result),
        )

    console.print(
        Panel(
            table,
            title="[bold]Details[/bold]",
            border_style="cyan",
            padding=(1, 1),
        )
    )


def print_modules(results: list[ModuleResult]) -> None:
    if not results:
        return

    table = Table(box=None, padding=(0, 2), show_header=True, header_style="bold")
    table.add_column("Module", style="bold cyan")
    table.add_column("Status", justify="right")
    table.add_column("Details", overflow="fold")

    for result in results:
        status = Text("ok", style="green") if result.ok else Text("error", style="red")
        details = result.error if result.error else result.summary
        table.add_row(result.name, status, details)

    console.print(
        Panel(
            table,
            title="[bold]Modules[/bold]",
            border_style="cyan",
            padding=(1, 1),
        )
    )


def build_payload(
    host: str,
    open_ports: list[int],
    probes: dict[int, ProbeResult],
    modules: list[ModuleResult] | None = None,
) -> dict:
    # JSON export format; ports without a probe result still get an entry.
    entries = []
    for port in sorted(set(open_ports)):
        entry = {
            "port": port,
            "service": COMMON_PORTS.get(port, "unknown"),
            "banner": None,
            "http_status": None,
            "headers": [],
            "error": None,
        }
        result = probes.get(port)
        if result:
            entry.update(result.to_dict())
        entries.append(entry)

    payload = {
        "target": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_port_count": len(entries),
        "open_ports": entries,
    }
    if modules:
        payload["modules"] = [result.to_dict() for result in modules]
    return payload


def write_json(path: str, payload: dict) -> bool:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if path == "-":
        # Machine-readable output only; never mix in the Rich table (H6).
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        return True

    file = Path(path)
    try:
        file.parent.mkdir(parents=True, exist_ok=True)  # M2
        fd, tmp_name = tempfile.mkstemp(
            prefix=file.name + ".", suffix=".tmp", dir=str(file.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text + "\n")
            os.replace(tmp_name, file)  # atomic (L7)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
    except OSError as exc:
        error_console.print(
            f"[red]Could not write JSON to[/red] {escape(str(file))}: {exc}"
        )
        return False

    console.print(f"[green]JSON written to[/green] {escape(str(file))}")
    return True


async def scan_port_addr(
    connect_hosts: str | list[str], port: int, timeout: float = 1.0
) -> str:
    # A completed TCP handshake means the port is open; return the winning address.
    if isinstance(connect_hosts, str):
        connect_hosts = [connect_hosts]
    for connect_host in connect_hosts:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError):
            continue
        except Exception:
            continue
        await close_stream(writer)
        return connect_host
    return ""


async def scan_port(
    connect_hosts: str | list[str], port: int, timeout: float = 1.0
) -> bool:
    return bool(await scan_port_addr(connect_hosts, port, timeout))


async def scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    probe_timeout: float = 2.0,
    do_probe: bool = True,
    verbose: bool = True,
) -> tuple[list[int], dict[int, ProbeResult]]:
    # Resolve every address once, then scan each port across all of them (C1).
    ascii_host = to_ascii_host(host)
    connect_hosts = await resolve_hosts(ascii_host)

    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def bounded(port: int) -> tuple[int, str]:
        async with sem:
            try:
                return port, await scan_port_addr(connect_hosts, port, timeout)
            except Exception:
                return port, ""

    results = await asyncio.gather(
        *(bounded(port) for port in ports), return_exceptions=True
    )

    open_ports: dict[int, str] = {}
    for port, outcome in zip(ports, results):
        if isinstance(outcome, BaseException):
            continue
        if outcome[1]:
            open_ports[port] = outcome[1]
    open_ports = dict(sorted(open_ports.items()))

    if verbose:
        table = Table(box=None, padding=(0, 2), show_header=False)
        table.add_column("Status", justify="right", style="bold green")
        table.add_column("Port", justify="right", style="bold cyan")
        table.add_column("", style="dim")
        table.add_column("Service", style="white")

        for port in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            table.add_row("[green]+[/green]", str(port), "/", service)

        summary = Text.assemble(
            ("  Target: ", "bold"), (host, "bold cyan"), "\n",
            ("  ", ""), (str(len(open_ports)), "bold"),
            (f" open port{'s' if len(open_ports) != 1 else ''} found\n", ""),
        )

        console.print(
            Panel(table, title="[bold]Results[/bold]", border_style="cyan", padding=(1, 1))
        )
        console.print(summary)

    probes: dict[int, ProbeResult] = {}
    if do_probe and open_ports:
        if verbose:
            console.print(
                f"[bold]Grabbing banners/headers[/bold] "
                f"[dim]({len(open_ports)} open port{'s' if len(open_ports) != 1 else ''})[/dim]"
            )
        probes = await probe_ports(host, open_ports, probe_timeout)
        if verbose:
            print_details(probes)

    return sorted(open_ports), probes


def parse_target(target: str) -> tuple[str, int, str]:
    # Accept bare hosts; default the port from the URL scheme.
    target = target.strip()
    if not target:
        raise ValueError("target is empty")

    if target.startswith("//"):
        target = "http:" + target
    elif "://" not in target:
        bare = target.split("/", 1)[0]
        try:
            ip = ipaddress.ip_address(bare)
        except ValueError:
            target = "http://" + target
        else:
            if ip.version == 6:
                target = f"http://[{bare}]" + target[len(bare):]
            else:
                target = "http://" + target

    parsed = urlparse(target)

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in URL: {exc}") from exc

    host = parsed.hostname
    if not host:
        raise ValueError(f"could not determine host from {target!r}")

    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not (0 < port <= 65535):
        raise ValueError(f"port out of range: {port}")
    return host, port, parsed.scheme.lower()


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty port in {spec!r}")
        if "-" in part:
            bits = part.split("-")
            if len(bits) != 2 or not bits[0].strip() or not bits[1].strip():
                raise ValueError(f"bad range {part!r}")
            try:
                lo, hi = int(bits[0]), int(bits[1])
            except ValueError as exc:
                raise ValueError(f"bad range {part!r}") from exc
            if lo > hi:
                raise ValueError(f"reversed range {part!r}")
        else:
            try:
                lo = hi = int(part)
            except ValueError as exc:
                raise ValueError(f"invalid port {part!r}") from exc
        if not (0 < lo <= 65535 and 0 < hi <= 65535):
            raise ValueError(f"port out of range in {part!r}")
        ports.update(range(lo, hi + 1))

    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Fast async port scanner with banner/header inspection and optional "
            "scan modules."
        ),
        usage="python scanner.py <url> [--modules dns,robots]",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "-p", "--ports",
        default=None,
        help="Ports to scan, e.g. '80,443,8080' or '1-1024' (default: common ports)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--probe-timeout",
        type=float,
        default=2.0,
        help="Timeout for banner/header reads in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing and HTTP header inspection",
    )
    parser.add_argument(
        "-o", "--json",
        dest="json",
        metavar="FILE",
        default=None,
        help="Export results as JSON to FILE ('-' for stdout)",
    )
    parser.add_argument(
        "--modules",
        default=None,
        help="Comma-separated scan modules: dns, robots",
    )
    parser.add_argument(
        "--all-modules",
        action="store_true",
        help="Run every available scan module",
    )
    parser.add_argument(
        "--dns-server",
        default=None,
        help="DNS resolver for the dns module (IP or [IPv6]:port)",
    )
    parser.add_argument(
        "--module-timeout",
        type=float,
        default=5.0,
        help="Timeout for scan modules in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--skip-port-scan",
        action="store_true",
        help="Run scan modules without scanning ports",
    )
    args = parser.parse_args()

    try:
        host, default_port, scheme = parse_target(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.probe_timeout <= 0:
        parser.error("--probe-timeout must be greater than 0")
    if args.module_timeout <= 0:
        parser.error("--module-timeout must be greater than 0")

    if args.all_modules and args.modules:
        parser.error("--all-modules cannot be combined with --modules")

    module_names: list[str] = []
    if args.all_modules:
        module_names = list(MODULES)
    elif args.modules:
        try:
            module_names = parse_module_names(args.modules)
        except ValueError as exc:
            parser.error(str(exc))

    if args.skip_port_scan and not module_names:
        parser.error("--skip-port-scan requires --modules or --all-modules")

    if args.dns_server and "dns" not in module_names:
        parser.error("--dns-server requires the dns module")

    if args.dns_server:
        try:
            parse_dns_server(args.dns_server)
        except ValueError as exc:
            parser.error(str(exc))

    ports: list[int] = []
    if not args.skip_port_scan:
        if args.ports:
            try:
                ports = parse_ports(args.ports)
            except ValueError as exc:
                parser.error(str(exc))
        else:
            ports = sorted(COMMON_PORTS)
            if default_port not in ports:
                ports.append(default_port)
            ports = sorted(set(ports))  # deduplicate (M3)

    json_stdout = args.json == "-"
    if not json_stdout:
        scope: list[str] = []
        if not args.skip_port_scan:
            scope.append(f"{len(ports)} ports")
        if module_names:
            plural = "s" if len(module_names) != 1 else ""
            scope.append(f"{len(module_names)} module{plural}")
        console.print(
            f"\n[bold]Scanning[/bold] [cyan]{escape(host)}[/cyan] "
            f"[dim]({', '.join(scope)})[/dim]"
        )

    async def run_scan() -> tuple[
        list[int], dict[int, ProbeResult], list[ModuleResult]
    ]:
        open_ports: list[int] = []
        probes: dict[int, ProbeResult] = {}

        if not args.skip_port_scan:
            open_ports, probes = await scan(
                host,
                ports,
                args.timeout,
                args.probe_timeout,
                not args.no_banner,
                verbose=not json_stdout,
            )

        modules: list[ModuleResult] = []
        if module_names:
            if not json_stdout:
                console.print(
                    "[bold]Running scan modules[/bold] "
                    f"[dim]({', '.join(module_names)})[/dim]"
                )
            modules = await run_modules(
                host,
                default_port,
                scheme,
                module_names,
                args.module_timeout,
                args.dns_server,
            )

        return open_ports, probes, modules

    try:
        open_ports, probes, modules = asyncio.run(run_scan())
    except KeyboardInterrupt:
        error_console.print("\n[red]Interrupted[/red]")
        sys.exit(1)

    if not json_stdout:
        print_modules(modules)

    if args.json and not write_json(
        args.json, build_payload(host, open_ports, probes, modules)
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()