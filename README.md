# MTU / PMTUD Blackhole Hunter

A Python CLI for the "small pings work, HTTPS hangs" class of problem. It probes the path to a host with don't-fragment pings of decreasing size, compares a plain TCP handshake with a full TLS fetch, and prints a verdict with remediation steps and an exit code that scripts can act on.

Path MTU discovery breaks when a link in the path has a smaller MTU and the ICMP "fragmentation needed" message never makes it back. Small packets such as pings and TCP handshakes get through, but full-size TLS records are dropped. This tool looks for that pattern.

## What it checks

1. **DNS.** Resolves the destination first and exits with code 4 if that fails.
2. **Plain ping.** Sends one normal ping. If it gets no reply, the host or a firewall drops ICMP echo, and the DF ladder in the next step cannot say anything about MTU, so its failures are not counted as MTU evidence.
3. **DF ping ladder.** Sends one ping with the don't-fragment bit set at each IPv4 payload size from 1472 bytes (a 1500-byte packet) down to 1232 bytes in 40-byte steps, and records which sizes got a reply. Linux sets DF with `ping -M do` and macOS with `ping -D`. Each ping waits up to 2 seconds (`-W 2` on Linux, `-t 2` on macOS, because macOS `-W` counts milliseconds).
4. **Path trace.** Runs `tracepath -n -m 20` on Linux, which reports the path MTU hop by hop. On macOS, where tracepath is not available, it falls back to `traceroute -n -F -m 20 -q 1 -w 2`, which gives the hop list with DF set but does not measure MTU. Either one is cut off after 60 seconds and keeps the hops it printed by then.
5. **TCP handshake.** Opens a TCP connection to the destination port (443 by default) with a 3 second timeout.
6. **TLS fetch.** Runs `curl` against `https://<dest>:<port>/` and reports DNS lookup, connect, TLS, time to first byte and total time. curl gets 5 seconds to connect and 20 seconds in all, because a PMTUD blackhole makes the TLS step hang rather than fail.

## Verdict and exit codes

| Code | Verdict | Condition |
|------|---------|-----------|
| 0 | No clear MTU issue detected | None of the conditions below |
| 2 | Probable MTU/PMTUD issue | The plain ping works and either no DF ping size succeeded or the largest working size is below 1400 bytes, or TCP connects but the curl TLS fetch fails |
| 3 | TCP connectivity failure | TCP connect failed and no MTU signs were found |
| 4 | DNS resolution failed | The destination did not resolve |

For exit code 2 the tool prints the evidence that led to the verdict and remediation steps: standardize the link MTU at 1500 where possible, enable MSS clamping on the egress path or NAT, or stop middleboxes from setting DF, and check the hop where tracepath shows the MTU drop.

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

Example output from Linux with a 1300 byte link between the router and the server (the namespace lab in the tests):

```text
=== MTU / PMTUD Blackhole Hunter ===
DF probe: first success at payload 1272 bytes
DF ladder OK: [1272, 1232]
DF ladder FAIL: [1472, 1432, 1392, 1352, 1312]
TCP handshake to 10.78.2.2:8443: OK in 0.000s
curl timing: n/a

--- tracepath/traceroute ---
1?: [LOCALHOST]                      pmtu 1500
 1:  10.78.1.1                                             0.024ms
 1:  10.78.1.1                                             0.003ms
 2:  10.78.1.1                                             0.003ms pmtu 1300
 2:  10.78.2.2                                             0.008ms reached
     Resume: pmtu 1300 hops 2 back 2

=== Verdict ===
Probable MTU/PMTUD issue.
Evidence:
  • DF probes fail at common sizes (below 1400)
  • TCP handshake OK but TLS fetch failed (possible PMTUD blackhole)
Remediation:
...
```

The largest working payload, 1272 bytes, plus 28 bytes of IP and ICMP headers is the 1300 byte link, and tracepath names the hop where the MTU drops. The TLS line fails here because the lab's listener on port 8443 does not speak TLS.

## Tests

`tests/test_mtu_hunter.py` uses only the standard library `unittest`:

- Unit tests replace ping, curl and the TCP connect with fakes. They check the ping command on Linux (`-M do -W 2`) and macOS (`-D -t 2`), the ladder sizes, that the best size is the largest that works, every verdict and exit code (0, 2, 3 and 4), that a host which ignores ping is not reported as an MTU problem, the usage error without `--dest`, and that a slow command is cut off.
- A loopback test runs the real tool against 127.0.0.1 port 9. Loopback passes every DF size and port 9 is closed, so it has to exit 3.
- A stand in ping test runs the real tool with `tests/fake_ping/ping` first in `PATH`. The stand in acts like a path with a 1300 byte link: a DF ping whose packet would be bigger fails the way the real one does, and every other ping goes to the real `ping`. The tool has to exit 2 with `first success at payload 1272 bytes`, and the stand in's log has to show `-c 1 -t 2 -D -s 1472` on macOS or `-c 1 -W 2 -M do -s 1472` on Linux. This runs the low MTU branch of the current platform without root.
- An internet test runs the tool against example.com. It is skipped when example.com:443 cannot be reached.
- On Linux as root, a namespace lab test builds client, router and server namespaces with a 1300 byte link in the middle and checks that the tool exits 2 with `first success at payload 1272 bytes` and that tracepath reports `pmtu 1300`. Without root it is skipped.
- On macOS with `MTU_HUNTER_LO0_TEST=1` and passwordless sudo, a loopback test sets `lo0` to MTU 1300, adds the test address 192.0.2.98, checks that the real `ping -D` gets 1272 bytes of payload through and not 1273, checks that the tool exits 2 with `first success at payload 1272 bytes`, and puts `lo0` back. It changes a system setting, so it only runs when asked.

```bash
python3 -m unittest discover -s tests -v                        # any machine
sudo python3 -m unittest discover -s tests -v                   # Linux, adds the namespace lab
MTU_HUNTER_LO0_TEST=1 python3 -m unittest discover -s tests -v  # macOS with passwordless sudo, adds the loopback test
```

The GitHub Actions workflow in `.github/workflows/tests.yml` runs the tests as root on Ubuntu 24.04 and on macOS with `MTU_HUNTER_LO0_TEST=1`, since GitHub's macOS runners have passwordless sudo.

## Limitations

- The ladder uses IPv4 payload sizes. IPv6 paths are not probed separately.
- When the host does not answer ping, the ladder is reported but not used, so the verdict rests on the TCP and TLS steps alone.
- The TLS step assumes the port serves HTTPS. Any curl failure, such as a certificate error, counts toward the TLS heuristic.
