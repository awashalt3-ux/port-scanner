![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Rich](https://img.shields.io/badge/rich-15.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

# Port Scanner

Fast async port scanner. Give it a URL, it finds open ports.

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

## Examples

```bash
# Scan common ports
python scanner.py https://example.com

# Scan specific ports
python scanner.py http://scanme.nmap.org -p 22,80,443

# Scan a range with custom timeout
python scanner.py example.com -p 1-1000 -t 0.5
```

## License

MIT