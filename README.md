![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Rich](https://img.shields.io/badge/rich-15.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

# Port Scanner

Fast async port scanner. Give it a URL, it finds open ports, then grabs
service banners and HTTP response headers for the open ports.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py <url>
```

| Flag | Description | Example |
|------|-------------|---------|
| `-p` | Ports to scan (comma-separated or range) | `-p 80,443,8080` or `-p 1-1000` |
| `-t` | Connection timeout in seconds | `-t 0.5` |
| `--probe-timeout` | Timeout for banner/header reads in seconds (default: 2.0) | `--probe-timeout 3` |
| `--no-banner` | Skip banner grabbing and HTTP header inspection | `--no-banner` |
| `-o`, `--json` | Export results as JSON to a file (`-` for stdout) | `--json scan.json` |

## Banners and headers

After the port scan, each open port is probed in parallel:

- Ports known to speak HTTP (`80`, `443`, `8080`, `8443`, `8888`) receive a
  `GET / HTTP/1.1` request; the status line and response headers are shown
  (capped at 12 headers).
- Other open ports are read for a service banner (SSH, FTP, SMTP, etc.).
  If the banner starts with `HTTP/`, an HTTP request is sent instead.
- HTTPS ports use an unverified TLS context so self-signed/internal
  certificates do not fail the probe.

Results are printed in a **Details** section under the open-ports table.

Probing is fast: ports are scanned 256 at a time, probes run 100 at a time,
DNS is resolved once per scan, and banner reads stop after 0.2s of inactivity,
so silent ports do not stall the scan.

## JSON export

```bash
# Write results to scan.json
python scanner.py example.com --json scan.json

# Print JSON to stdout
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
      "headers": {"Server": "cloudflare", "Content-Type": "text/html"},
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

# Scan a range with custom timeout
python scanner.py example.com -p 1-1000 -t 0.5

# Find open ports without probing banners/headers
python scanner.py example.com --no-banner
```

## License

MIT