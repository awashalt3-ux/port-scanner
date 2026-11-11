#!/usr/bin/env python3
"""Fast async port scanner with banner grabbing and HTTP header inspection."""

import argparse
import asyncio
import ipaddress
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS",
    995: "POP3S", 1433: "MS SQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP Alt", 8443: "HTTPS Alt", 8888: "HTTP Alt", 27017: "MongoDB",
}

HTTP_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8888})
TLS_PORTS: frozenset[int] = frozenset({443, 8443})

PROBE_CONCURRENCY = 100
SCAN_CONCURRENCY = 256
BANNER_IDLE_TIMEOUT = 0.2
MAX_BANNER_BYTES = 1024
MAX_HEADER_LINES = 12
MAX_HEADER_VALUE = 120
MAX_BANNER_TEXT = 200


@dataclass
class ProbeResult:
    port: int
    banner: str = ""
    http_status: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "banner": self.banner or None,
            "http_status": self.http_status or None,
            "headers": {name: value for name, value in self.headers},
            "error": self.error or None,
        }


def clean_text(data: bytes, limit: int = MAX_BANNER_TEXT) -> str:
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


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def open_stream(
    connect_host: str,
    port: int,
    use_tls: bool,
    timeout: float,
    sni_host: str = "",
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ctx = tls_context() if use_tls else None
    target = sni_host if use_tls and sni_host else connect_host
    return await asyncio.wait_for(
        asyncio.open_connection(target, port, ssl=ctx), timeout=timeout
    )


async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return host

    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            return sockaddr[0]
    return host


async def close_stream(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass


async def read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    chunks = bytearray()

    while len(chunks) < MAX_BANNER_BYTES:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            byte = await asyncio.wait_for(
                reader.read(1), timeout=min(BANNER_IDLE_TIMEOUT, remaining)
            )
        except (asyncio.TimeoutError, OSError):
            break
        if not byte:
            break
        chunks.extend(byte)

    return clean_text(bytes(chunks))


def parse_http_response(raw: bytes) -> tuple[str, list[tuple[str, str]]]:
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
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    except asyncio.IncompleteReadError as exc:
        return exc.partial
    except asyncio.LimitOverrunError:
        try:
            return await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return b""
    except (asyncio.TimeoutError, OSError):
        return b""


def build_http_request(host: str, port: int) -> str:
    host_header = f"[{host}]" if ":" in host else host
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
            connect_host, port, use_tls, timeout, sni_host=host
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
    finally:
        await close_stream(writer)


async def grab_banner(
    connect_host: str, host: str, port: int, timeout: float
) -> ProbeResult:
    use_tls = port in TLS_PORTS
    try:
        reader, writer = await open_stream(
            connect_host, port, use_tls, timeout, sni_host=host
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
    if port in HTTP_PORTS:
        return await probe_http(connect_host, host, port, port in TLS_PORTS, timeout)

    result = await grab_banner(connect_host, host, port, timeout)
    if result.banner.upper().startswith("HTTP/"):
        return await probe_http(connect_host, host, port, port in TLS_PORTS, timeout)
    return result


async def probe_all(
    connect_host: str, host: str, ports: list[int], timeout: float
) -> dict[int, ProbeResult]:
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def bounded(port: int) -> tuple[int, ProbeResult]:
        async with sem:
            return port, await probe_port(connect_host, host, port, timeout)

    results = await asyncio.gather(*(bounded(p) for p in ports))
    return dict(results)


def format_probe(result: ProbeResult) -> Text:
    if result.error:
        return Text(result.error, style="red")

    lines: list[Text] = []
    if result.http_status:
        style = "bold green" if " 200 " in f" {result.http_status} " else "bold yellow"
        lines.append(Text.assemble(("HTTP  ", "bold"), (result.http_status, style)))
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


def build_payload(
    host: str, open_ports: list[int], probes: dict[int, ProbeResult]
) -> dict:
    entries = []
    for port in open_ports:
        entry = {
            "port": port,
            "service": COMMON_PORTS.get(port, "unknown"),
            "banner": None,
            "http_status": None,
            "headers": {},
            "error": None,
        }
        result = probes.get(port)
        if result:
            entry.update(result.to_dict())
        entries.append(entry)

    return {
        "target": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_port_count": len(open_ports),
        "open_ports": entries,
    }


def write_json(path: str, payload: dict) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if path == "-":
        print(text)
        return

    file = Path(path)
    file.write_text(text + "\n", encoding="utf-8")
    console.print(f"[green]JSON written to[/green] {file}")


async def scan_port(connect_host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port), timeout=timeout
        )
        await close_stream(writer)
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    probe_timeout: float = 2.0,
    do_probe: bool = True,
) -> tuple[list[int], dict[int, ProbeResult]]:
    connect_host = await resolve_host(host)

    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def bounded(p: int) -> tuple[int, bool]:
        async with sem:
            return p, await scan_port(connect_host, p, timeout)

    tasks = [bounded(p) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = sorted([(p, ok) for p, ok in results if ok])

    table = Table(box=None, padding=(0, 2), show_header=False)
    table.add_column("Status", justify="right", style="bold green")
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("", style="dim")
    table.add_column("Service", style="white")

    for p, _ in open_ports:
        service = COMMON_PORTS.get(p, "unknown")
        table.add_row("[green]+[/green]", str(p), "/", service)

    summary = Text.assemble(
        ("  Target: ", "bold"), (host, "bold cyan"), "\n",
        ("  ", ""), (f"{len(open_ports)}", "bold"),
        (f" open port{'s' if len(open_ports) != 1 else ''} found\n", ""),
    )

    console.print(Panel(table, title="[bold]Results[/bold]", border_style="cyan", padding=(1, 1)))
    console.print(summary)

    probes: dict[int, ProbeResult] = {}
    if do_probe and open_ports:
        console.print(
            f"[bold]Grabbing banners/headers[/bold] "
            f"[dim]({len(open_ports)} open port{'s' if len(open_ports) != 1 else ''})[/dim]"
        )
        probes = await probe_all(
            connect_host, host, [p for p, _ in open_ports], probe_timeout
        )
        print_details(probes)

    return [p for p, _ in open_ports], probes


def parse_target(target: str) -> tuple[str, int]:
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fast async port scanner with banner/header inspection.",
        usage="python scanner.py <url>",
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
    args = parser.parse_args()

    host, default_port = parse_target(args.url)

    if args.ports:
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                lo, hi = map(int, part.split("-"))
                ports.extend(range(lo, hi + 1))
            else:
                ports.append(int(part))
    else:
        ports = sorted(COMMON_PORTS)
        if default_port not in ports:
            ports.append(default_port)

    console.print(f"\n[bold]Scanning[/bold] [cyan]{host}[/cyan] [dim]({len(ports)} ports)[/dim]")

    try:
        open_ports, probes = asyncio.run(
            scan(host, ports, args.timeout, args.probe_timeout, not args.no_banner)
        )
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted[/red]")
        sys.exit(1)

    if args.json:
        write_json(args.json, build_payload(host, open_ports, probes))


if __name__ == "__main__":
    main()