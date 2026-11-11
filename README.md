<div align="center">

# Port Scanner

**A fast, async port scanner with banner grabbing, HTTP header inspection, and optional DNS/robots scan modules.**

![Port Scanner CLI output](docs/cli-scan.png)

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Rich](https://img.shields.io/badge/rich-13.0%2B-green)](https://github.com/Textualize/rich)
[![License](https://img.shields.io/badge/license-MIT-purple)](LICENSE)

</div>

---

## Features

- **Fast** — scans 256 ports and probes 100 services concurrently.
- **Dual-stack aware** — resolves every address and falls back across IPv4 and IPv6, so `localhost` works on either family.
- **Banner and header inspection** — grabs SSH, FTP, SMTP and other service banners, plus HTTP status lines and headers.
- **TLS support** — unverified contexts for self-signed and internal certificates.
- **JSON export** — machine-readable output with duplicate headers preserved.
- **Scan modules** — DNS record enumeration and `robots.txt` inspection, with a small registry for adding more checks.
- **Robust output** — UTF-8 safe, atomic file writes, and clear command-line validation.

## Install

Requires **Python 3.9+**. The DNS module uses `dnspython`, which is included in
`requirements.txt`.

```bash
pip install -r requirements.txt
```

Or install the project to get the `portscan` command:

```bash
pip install -e .
```

## Usage

```bash
python scanner.py <url>

# or, after an editable install
portscan <url>
```

### Options

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `-p`, `--ports` | Ports to scan (comma-separated or range) | common ports | `-p 80,443,8080` or `-p 1-1000` |
| `-t`, `--timeout` | Per-connection timeout in seconds (must be > 0) | `1.0` | `-t 0.5` |
| `--probe-timeout` | Banner/header read timeout in seconds (must be > 0) | `2.0` | `--probe-timeout 3` |
| `--no-banner` | Skip banner grabbing and header inspection | off | `--no-banner` |
| `--modules` | Comma-separated scan modules: `dns`, `robots` | off | `--modules dns,robots` |
| `--all-modules` | Run every registered scan module | off | `--all-modules` |
| `--dns-server` | DNS resolver for the `dns` module (`IP` or `[IPv6]:port`) | system resolver | `--dns-server 1.1.1.1` |
| `--module-timeout` | Timeout for scan modules in seconds (must be > 0) | `5.0` | `--module-timeout 3` |
| `--skip-port-scan` | Run scan modules without scanning ports | off | `--modules dns --skip-port-scan` |
| `-o`, `--json` | Write JSON to `FILE` (`-` for stdout) | off | `--json scan.json` |
| `-h`, `--help` | Show help and exit | | |
| `--version` | Show the scanner version and exit | | |

`-p` accepts single ports, comma-separated lists, and ranges. Empty entries,
reversed ranges (`443-80`), out-of-range ports, and malformed values are
rejected with a clear error; duplicate ports are collapsed.

## How it works

1. **Resolve** — the hostname is resolved once, and every address it returns is kept.
2. **Scan** — each port is opened with a bounded connection timeout. A completed TCP handshake marks the port open.
3. **Probe** — open ports are probed in parallel:
   - Known HTTP ports receive a `GET / HTTP/1.1` request.
   - Other ports are read for a service banner; an `HTTP/` banner triggers an HTTP request.
   - Silent ports are retried once with an HTTP request, so HTTP services on non-standard ports are still detected.
4. **Modules** — optional scan modules run after the port scan, or alone with
   `--skip-port-scan`.
5. **Report** — results are printed as tables and optionally exported to JSON.

Probing is fast: 256 ports are scanned at a time, probes run 100 at a time, DNS
is resolved once per scan, and banner reads stop after 0.2s of inactivity, so
silent ports do not stall the scan. Scan modules run up to 10 at a time.

### Networking notes

- **DNS and IPv6** — every address returned by the resolver is tried, so
  dual-stack targets work even when only one family is reachable. Scanning
  `localhost` finds IPv4-only services instead of stopping at `::1`.
- **Internationalised hostnames** — IDN targets are IDNA-encoded for DNS, SNI,
  and the `Host` header (for example, `münich.de` becomes `xn--mnich-kva.de`).
- **Output encoding** — non-ASCII banners and headers are written as UTF-8.
  On Windows consoles, the standard streams are reconfigured to UTF-8 with
  replacement characters, so a single non-cp1252 byte cannot abort output.
- **Scan modules** — DNS queries use the system resolver unless `--dns-server`
  is supplied. `robots.txt` is fetched over HTTP(S) with the same unverified TLS
  policy as the port probes, and the body is capped at 256 KiB.

## Scan modules

Modules are small, independent checks that run after the port scan. They are
defined in `scan_modules/` and registered in `scan_modules/__init__.py`.

| Module | What it does |
|--------|--------------|
| `dns` | Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, and `CAA` records, plus `PTR` records for resolved addresses. |
| `robots` | Fetches `/robots.txt`, parses `User-agent`, `Allow`, `Disallow`, `Crawl-delay`, and `Sitemap` entries, and reports the HTTP status. |

To add another check, implement `ScanModule` in `scan_modules/` and register the
instance in `scan_modules/__init__.py`.

```bash
# Run the port scan, then DNS and robots checks
python scanner.py https://example.com --modules dns,robots

# DNS-only reconnaissance; no port scan
python scanner.py example.com --modules dns --skip-port-scan

# Use a specific resolver (IP or [IPv6]:port)
python scanner.py example.com --modules dns --dns-server 1.1.1.1
```

Unknown module names are rejected with the list of available modules. The JSON
export includes a `modules` array when at least one module runs.

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

Repeated headers are preserved: `headers` is a list of `{name, value}` objects,
so `Set-Cookie`, `WWW-Authenticate`, `Link`, and similar headers are not
collapsed.

When modules run, the payload also includes a `modules` array:

```json
{
  "modules": [
    {
      "module": "dns",
      "ok": true,
      "summary": "A, AAAA, MX, NS, TXT",
      "data": {
        "records": {
          "A": ["93.184.216.34"],
          "MX": ["10 mail.example.com."]
        },
        "errors": {}
      },
      "error": null
    },
    {
      "module": "robots",
      "ok": true,
      "summary": "HTTP 200, 2 groups, 1 sitemap",
      "data": {
        "status": 200,
        "reason": "OK",
        "content_type": "text/plain",
        "body_bytes": 128,
        "groups": [],
        "sitemaps": ["https://example.com/sitemap.xml"]
      },
      "error": null
    }
  ]
}
```

## Examples

```bash
# Scan common ports
python scanner.py https://example.com

# Scan specific ports
python scanner.py http://scanme.nmap.org -p 22,80,443

# Scan a range with a custom timeout
python scanner.py example.com -p 1-1000 -t 0.5

# Find open ports without probing banners/headers
python scanner.py example.com --no-banner

# Run DNS and robots.txt checks after the port scan
python scanner.py example.com --modules dns,robots

# DNS-only check with a custom resolver
python scanner.py example.com --modules dns --skip-port-scan --dns-server 1.1.1.1

# Export results to a nested path
python scanner.py example.com --json reports/example.com.json
```

## Security notes

- TLS certificate verification is disabled by default so self-signed and
  internal certificates do not fail probes. Do not rely on these probes for
  trust decisions.
- Only scan systems you own or have explicit permission to test. Port scanning
  can be disruptive and may violate laws or acceptable-use policies.
- Scan modules make outbound requests to the target: DNS queries and HTTP(S)
  `GET` requests for `robots.txt`. Use the same authorization requirements as
  the port scan.

## License

Released under the [MIT License](LICENSE).