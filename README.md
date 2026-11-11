![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Rich](https://img.shields.io/badge/rich-13.0%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

# Port Scanner

Fast async port scanner. Give it a URL, it finds open ports, then grabs
service banners and HTTP response headers for the open ports.

## Install

```bash
pip install -r requirements.txt
```

Optionally install the project to get the `portscan` command:

```bash
pip install -e .
```

## Usage

```bash
python scanner.py <url>

# or, after an editable install
portscan <url>
```

| Flag | Description | Example |
|------|-------------|---------|
| `-p` | Ports to scan (comma-separated or range) | `-p 80,443,8080` or `-p 1-1000` |
| `-t` | Connection timeout in seconds (must be > 0) | `-t 0.5` |
| `--probe-timeout` | Timeout for banner/header reads in seconds (must be > 0, default: 2.0) | `--probe-timeout 3` |
| `--no-banner` | Skip banner grabbing and HTTP header inspection | `--no-banner` |
| `-o`, `--json` | Export results as JSON to a file (`-` for stdout) | `--json scan.json` |

`-p` accepts single ports, comma-separated lists and ranges. Empty entries,
reversed ranges (`443-80`), out-of-range ports and malformed values are
rejected with a clear error; duplicate ports are collapsed.

## Banners and headers

After the port scan, each open port is probed in parallel:

- Ports known to speak HTTP (`80`, `443`, `3000`, `5000`, `8000`, `8080`,
  `8081`, `8443`, `8888`, `9000`, `9090`) receive a `GET / HTTP/1.1`
  request; the status line and response headers are shown (capped at 12
  headers).
- Other open ports are read for a service banner (SSH, FTP, SMTP, etc.).
  If the banner starts with `HTTP/`, an HTTP request is sent instead.
- If a non-HTTP port stays silent, it is retried once with an HTTP request,
  so HTTP services on non-standard ports are still detected.
- HTTPS ports use an unverified TLS context so self-signed/internal
  certificates do not fail the probe. Connections are made to the resolved
  IP address while the original hostname is used for TLS SNI.

Results are printed in a **Details** section under the open-ports table.

Probing is fast: ports are scanned 256 at a time, probes run 100 at a time,
DNS is resolved once per scan, and banner reads stop after 0.2s of inactivity,
so silent ports do not stall the scan.

### Networking notes

- **DNS / IPv6:** every address returned by the resolver is tried, so
  dual-stack targets work even when only one family is reachable. Scanning
  `localhost` finds IPv4-only services instead of stopping at `::1`.
- **Internationalised hostnames:** IDN targets are IDNA-encoded for DNS, SNI
  and the `Host` header (e.g. `münich.de` → `xn--mnich-kva.de`).
- **Output encoding:** non-ASCII banners and headers are written as UTF-8.
  On Windows consoles the standard streams are reconfigured to UTF-8 with
  replacement characters, so a single non-cp1252 byte cannot abort output.

## JSON export

```bash
# Write results to scan.json (parent directories are created automatically)
python scanner.py example.com --json scan.json

# Print JSON to stdout (only JSON is written, so it can be piped)
python scanner.py example.com -p 80,443 --json -
```

Output shape:

```json
{
  "target": "example.com",
  "scanned_at": "2026-11-11T21:13:20+00:00",
  "open_port_count": 2,
  "open_ports": [
    {
      "port": 80,
      "service": "HTTP",
      "banner": null,
      "http_status": "HTTP/1.1 200 OK",
      "headers": [
        {"name": "Server", "value": "cloudflare"},
        {"name": "Content-Type", "value": "text/html"}
      ],
      "error": null
    }
  ]
}
```

Repeated headers are preserved: `headers` is a list of `{name, value}`
objects, so `Set-Cookie`, `WWW-Authenticate`, `Link` and similar headers are
not collapsed.

## Examples

```bash
# Scan common ports
python scanner.py https://example.com

# Scan specific ports
python scanner.py http://scanme.nmap.org -p 22,80,443

# Scan a range with custom timeout
python scanner.py example.com -p 1-1000 -t 0.5

# Find open ports without probing banners/headers
python scanner.py example.com --no-banner
```

## License

MIT