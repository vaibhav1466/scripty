# AutoRecon — Automated Bug Bounty Reconnaissance Pipeline

Turn a domain into a structured recon report in one command.

## Quick Start

```bash
chmod +x recon.sh
./recon.sh example.com
```

All output lands in `recon/example.com/`. Final report printed to stdout + saved as `report.txt`.

## Pipeline

```
Input: target.com
  │
  ├── Phase 1 — Subdomain Enumeration
  │     crt.sh → subfinder → AlienVault OTX
  │
  ├── Phase 2 — Live Host Discovery
  │     dnsx (or dig) → httpx (or curl)
  │
  ├── Phase 3 — Port Scanning
  │     naabu (or nc / /dev/tcp)
  │
  ├── Phase 4 — URL Discovery
  │     Wayback Machine → gau → OTX → href extraction → katana
  │     └── Extracts new subdomains from URLs & re-resolves them
  │
  ├── Phase 5 — JavaScript Analysis
  │     Download JS files → extract API endpoints → hunt secrets
  │
  ├── Phase 6 — Parameter & Endpoint Extraction
  │     Categorize params by vuln class (IDOR, LFI, SSRF, SQLi, …)
  │     Find juicy endpoints (/api/, /admin/, /graphql, /.git, …)
  │
  ├── Phase 7 — Nuclei Vulnerability Scan
  │     Critical / high / medium CVEs + subdomain takeover detection
  │
  └── Phase 8 — Report Generation
        Structured summary with findings & stats
```

## Features

- **Zero-config** — one argument, one command. No YAML, no API keys required.
- **Graceful degradation** — every tool (subfinder, dnsx, httpx, naabu, gau, katana, nuclei) can be missing. Falls back to curl, dig, nc, or pure-bash alternatives.
- **JS secret hunting** — scans JS for API keys, AWS access keys, private keys, tokens, and bearer auth strings.
- **Vuln-aware param extraction** — tags each parameter URL with its likely vulnerability class: `[IDOR]`, `[SSRF]`, `[SQLi/XSS]`, `[Open Redirect]`, etc.
- **Self-healing subdomain list** — extracts new subdomains from crawled URLs and re-resolves/re-probes them.
- **Portable** — Linux and macOS. Detects GNU vs BSD grep and adjusts regex flags.
- **Structured output** — every phase writes to its own file. Final report aggregates everything.

## Output Structure

```
recon/<target>/
├── report.txt                 # Final human-readable report
├── recon.log                  # Full stderr log for debugging
├── errors.log                 # Only errors/warnings
├── subdomains.txt             # All discovered subdomains (deduplicated)
├── dns_resolved.txt           # Subdomains that resolved to an IP
├── live_hosts.txt             # URLs confirmed reachable via HTTP(S)
├── httpx_output.txt           # httpx output with status codes + tech
├── open_ports.txt             # Open port:service pairs
├── urls.txt                   # Every discovered URL (deduplicated)
├── interesting_endpoints.txt  # Juicy endpoints (/api/, /admin/, etc.)
├── interesting_params.txt     # URLs containing query parameters
├── params_by_type.txt         # Parameters tagged by vulnerability class
├── js_files.txt               # JS file URLs selected for analysis
├── js_endpoints.txt           # URLs & paths extracted from JS
├── js_secrets.txt             # Potential secrets found in JS
├── nuclei_results.txt         # Nuclei vulnerability findings
├── nuclei_takeover.txt        # Subdomain takeover candidates
└── js_downloads/              # Downloaded JS files (cleaned up by default)
```

## Requirements

**Must have:** bash (>=4.0), curl, jq, grep, sed, sort

**Strongly recommended** (fallback available):
- [subfinder](https://github.com/projectdiscovery/subfinder) — passive subdomain enumeration
- [dnsx](https://github.com/projectdiscovery/dnsx) — fast DNS resolution
- [httpx](https://github.com/projectdiscovery/httpx) — live host probing with tech detection
- [naabu](https://github.com/projectdiscovery/naabu) — port scanning
- [gau](https://github.com/lc/gau) — multi-source URL gathering
- [katana](https://github.com/projectdiscovery/katana) — active crawling
- [nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanning + takeover detection

### Quick Install

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `JS_LIMIT` | `30` | Max JS files to download & analyze |
| `CLEANUP_TEMP` | `true` | Remove intermediate files after completion |

```bash
JS_LIMIT=100 CLEANUP_TEMP=false ./recon.sh example.com
```

## Examples

```bash
# Basic recon
./recon.sh hackerone.com

# Deep JS analysis
JS_LIMIT=100 ./recon.sh shopify.com

# Keep temp files for debugging
CLEANUP_TEMP=false ./recon.sh bugcrowd.com

# Local network target (CTF / HTB)
./recon.sh 10.10.10.10
```

## Fallback Behavior

| Missing tool | Falls back to |
|---|---|
| subfinder | crt.sh + AlienVault OTX |
| dnsx | parallel dig with xargs -P20 |
| httpx | parallel curl probes |
| naabu | nc sweep + pure-bash /dev/tcp |
| gau | Wayback Machine + OTX + inline href extraction |
| katana | skipped (URL discovery uses other sources) |
| nuclei | skipped, report notes its absence |

## Limitations

- **Passive-only subdomain discovery** — no DNS brute force. Relies on crt.sh, subfinder (API keys), and OTX.
- **WAF-heavy targets** — Cloudflare blocks nuclei, some JS downloads, and deep crawling. The script handles this gracefully with empty results.
- **Wayback rate limits** — the CDX API may throttle requests from some IPs.
- **Nuclei on large targets** — scanning 37+ hosts can take >10 minutes. Run separately on subsets if needed.
- **No cloud asset enumeration** — S3 buckets, Firebase, and other cloud storage are not checked.

## License

MIT

## Disclaimer

For authorized security testing only. You are responsible for complying with all applicable laws and bug bounty program rules. Do not run this against any target without explicit permission.
