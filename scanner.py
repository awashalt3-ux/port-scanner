#!/usr/bin/env python3
"""Fast async port scanner. Give it a URL, it finds open ports."""

import argparse
import asyncio
import sys
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


async def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan(host: str, ports: list[int], timeout: float = 1.0) -> None:
    sem = asyncio.Semaphore(100)

    async def bounded(p: int) -> tuple[int, bool]:
        async with sem:
            return p, await scan_port(host, p, timeout)

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
        ("  ", ""), (f"{len(open_ports)}", "bold"), (f" open port{'s' if len(open_ports) != 1 else ''} found\n", ""),
    )

    console.print(Panel(table, title="[bold]Results[/bold]", border_style="cyan", padding=(1, 1)))
    console.print(summary)


def parse_target(target: str) -> tuple[str, int]:
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fast async port scanner. Give it a URL.",
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
        asyncio.run(scan(host, ports, args.timeout))
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()