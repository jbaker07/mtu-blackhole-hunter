# MTU / PMTUD Blackhole Hunter (MVP)

Diagnose “small pings work, HTTPS fails” with a fast, structured probe:
- DF ladder (1472 → 1200 bytes) to detect PMTUD/MTU issues
- `tracepath` hop MTU hints
- TCP handshake test (SYN/SYN-ACK) vs TLS fetch timing (curl)
- Clear remediation (set link MTU / MSS clamp) and exit code

## Requirements
- Linux/macOS with: `ping`, `tracepath` (or `traceroute -F` on macOS), `curl`, Python 3.8+

## Quick start
```bash
python3 mtu_hunter.py --dest example.com --port 443
