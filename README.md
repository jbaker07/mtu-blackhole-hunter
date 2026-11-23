# MTU / PMTUD Blackhole Hunter

A Python CLI for the "small pings work, HTTPS hangs" class of problem. It probes the path to a host with don't-fragment pings of decreasing size, compares a plain TCP handshake with a full TLS fetch, and prints a verdict with remediation steps and an exit code that scripts can act on.

Path MTU discovery breaks when a link in the path has a smaller MTU and the ICMP "fragmentation needed" message never makes it back. Small packets such as pings and TCP handshakes get through, but full-size TLS records are dropped. This tool looks for that pattern.

## What it checks

1. **DNS.** Resolves the destination first and exits with code 4 if that fails.
2. **DF ping ladder.** Sends one ping with the don't-fragment bit set at each IPv4 payload size from 1472 bytes (a 1500-byte packet) down to 1232 bytes in 40-byte steps, and records which sizes got a reply.
3. **Path trace.** Runs `tracepath -n` on Linux, which reports the path MTU hop by hop. On macOS, where tracepath is not available, it falls back to `traceroute -n -F`, which gives the hop list with DF set but does not measure MTU.
4. **TCP handshake.** Opens a TCP connection to the destination port (443 by default) with a 3 second timeout.
5. **TLS fetch.** Runs `curl` against `https://<dest>:<port>/` and reports DNS lookup, connect, TLS, time to first byte and total time.

## Verdict and exit codes

| Code | Verdict | Condition |
|------|---------|-----------|
| 0 | No clear MTU issue detected | None of the conditions below |
| 2 | Probable MTU/PMTUD issue | No DF ping size succeeded, or the largest working size is below 1400 bytes, or TCP connects but the curl TLS fetch fails |
| 3 | TCP connectivity failure | TCP connect failed and no MTU signs were found |
| 4 | DNS resolution failed | The destination did not resolve |

For exit code 2 the tool prints remediation steps: standardize the link MTU at 1500 where possible, enable MSS clamping on the egress path or NAT, or stop middleboxes from setting DF, and check the hop where tracepath shows the MTU drop.

## Requirements

- Python 3
- `ping` and `curl`
- `tracepath` on Linux (from iputils) or `traceroute` on macOS

## Usage

```bash
python3 mtu_hunter.py --dest example.com --port 443
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dest` | required | Destination host name or IPv4 address |
| `--port` | `443` | TCP port for the handshake and the HTTPS fetch |

Example output from a macOS run (the traceroute hop list is shortened here):

```text
=== MTU / PMTUD Blackhole Hunter ===
DF probe: first success at payload 1472 bytes
DF ladder OK: [1472, 1432, 1392, 1352, 1312, 1272, 1232]
DF ladder FAIL: none
TCP handshake to one.one.one.one:443: OK in 0.015s
curl timing → lookup:0.003441 connect:0.016805 tls:0.037355 ttfb:0.072717 total:0.074318

--- tracepath/traceroute ---
...
 9  1.0.0.1  21.360 ms  13.555 ms  10.879 ms

=== Verdict ===
No clear MTU issue detected.
```

## Limitations

- The ladder uses IPv4 payload sizes. IPv6 paths are not probed separately.
- A host that drops ICMP echo fails every DF ping, and the tool reports that as a probable MTU issue. Check that the host answers a normal ping before trusting that verdict.
- The TLS step assumes the port serves HTTPS. Any curl failure, such as a certificate error, counts toward the TLS heuristic.
- On macOS the traceroute fallback can take a while on paths with many silent hops.
