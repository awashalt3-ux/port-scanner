from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field

from .base import ascii_host

MAX_HEAD_BYTES = 64 * 1024
MAX_BODY_BYTES = 256 * 1024


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return ""


def split_http_response(raw: bytes) -> tuple[bytes, bytes] | None:
    crlf = raw.find(b"\r\n\r\n")
    lf = raw.find(b"\n\n")
    if crlf != -1 and (lf == -1 or crlf <= lf):
        return raw[: crlf + 4], raw[crlf + 4 :]
    if lf != -1:
        return raw[: lf + 2], raw[lf + 2 :]
    return None


def parse_http_response(raw: bytes) -> HttpResponse | None:
    parts = split_http_response(raw)
    if parts is None:
        return None

    head, body = parts
    text = head.decode("iso-8859-1", errors="replace")
    lines = re.split(r"\r?\n", text)
    if not lines:
        return None

    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$", lines[0].strip())
    if match is None:
        return None

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[:1] in " \t" and headers:
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {line.strip()}")
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    return HttpResponse(
        status=int(match.group(1)),
        reason=(match.group(2) or "").strip(),
        headers=headers,
        body=body,
    )


async def read_response(reader: asyncio.StreamReader, timeout: float, max_body_bytes: int) -> bytes:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    buf = bytearray()
    limit = MAX_HEAD_BYTES + max_body_bytes

    while len(buf) < limit:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=remaining)
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)

    return bytes(buf)


async def _close_stream(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


def build_request(host: str, port: int, scheme: str, path: str) -> str:
    host = ascii_host(host)
    host_header = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        host_header += f":{port}"

    path = "/" + path.lstrip("/")
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: portscan/1.1\r\n"
        "Accept: text/plain, */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )


async def fetch_http(
    host: str,
    port: int,
    scheme: str,
    path: str,
    timeout: float,
    max_body_bytes: int = MAX_BODY_BYTES,
) -> HttpResponse:
    scheme = scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme}")

    connect_host = ascii_host(host)
    kwargs: dict[str, object] = {"limit": 1 << 20}
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["ssl"] = context
        kwargs["server_hostname"] = connect_host

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(connect_host, port, **kwargs), timeout=timeout
    )

    try:
        writer.write(build_request(host, port, scheme, path).encode("ascii"))
        await writer.drain()
        raw = await read_response(reader, timeout, max_body_bytes)
    finally:
        await _close_stream(writer)

    response = parse_http_response(raw)
    if response is None:
        raise ValueError("response did not contain an HTTP header block")
    return response
