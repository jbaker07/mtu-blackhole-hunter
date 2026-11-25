import argparse, subprocess, sys, shutil, socket, time, re

SIZES = list(range(1472, 1199, -40))  # DF ladder for IPv4 (payload sizes)

def run(cmd, timeout=None):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        # keep whatever the command printed before the time limit
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return 124, partial.strip(), f"timed out after {timeout}s"
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def have(cmd):
    return shutil.which(cmd) is not None

def ping_timeout_args():
    # Linux ping -W is seconds. macOS ping -W is milliseconds, so macOS uses -t,
    # which is an overall timeout in seconds.
    if sys.platform == "darwin":
        return ["-t", "2"]
    return ["-W", "2"]

def icmp_reachable(dest):
    """True when a plain ping (no DF bit, default size) gets a reply."""
    if not have("ping"):
        return False
    rc, _, _ = run(["ping", "-c", "1"] + ping_timeout_args() + [dest])
    return rc == 0

def df_ping(dest):
    """Return first working DF size, and per-size results."""
    results = []
    best = None
    for s in SIZES:
        if have("ping"):
            # Linux sets the don't-fragment bit with -M do, macOS with -D
            cmd = ["ping", "-c", "1"] + ping_timeout_args()
            if sys.platform == "darwin":
                cmd += ["-D", "-s", str(s)]
            else:
                cmd += ["-M", "do", "-s", str(s)]
            cmd += [dest]
            rc, out, _ = run(cmd)
            ok = (rc == 0)
            results.append((s, ok))
            if ok and best is None:
                best = s
        else:
            break
    return best, results

def trace_path(dest):
    # 20 hops and one probe per hop keep this under a minute on paths with silent hops
    if have("tracepath"):
        rc, out, _ = run(["tracepath", "-n", "-m", "20", dest], timeout=60)
        return out
    elif have("traceroute"):
        # macOS fallback, not the same as tracepath but provides hop context
        rc, out, _ = run(["traceroute", "-n", "-F", "-m", "20", "-q", "1", "-w", "2", dest], timeout=60)
        return out
    return ""

def tcp_handshake(dest, port, timeout=3.0):
    try:
        t0 = time.time()
        with socket.create_connection((dest, port), timeout=timeout):
            dt = (time.time() - t0)
            return True, dt
    except Exception:
        return False, None

def curl_tls_timing(dest, port):
    if not have("curl"):
        return None
    url = f"https://{dest}:{port}/"
    # A PMTUD blackhole makes the TLS step hang rather than fail, so curl gets a hard time limit
    rc, out, _ = run([
        "curl","-sS","--connect-timeout","5","--max-time","20","-o","/dev/null","-w",
        "lookup:%{time_namelookup} connect:%{time_connect} tls:%{time_appconnect} ttfb:%{time_starttransfer} total:%{time_total}",
        url
    ])
    return out if rc == 0 else None

def summarize(best_df, ladder, tcp_ok, tcp_dt, curl_t, trace_out, dest, port, icmp_ok=True):
    lines = []
    lines.append("=== MTU / PMTUD Blackhole Hunter ===")
    if not icmp_ok:
        lines.append("ICMP echo: no reply to a plain ping, so the DF ladder below proves nothing about MTU")
    if best_df is not None:
        lines.append(f"DF probe: first success at payload {best_df} bytes")
    elif icmp_ok:
        lines.append("DF probe: no size succeeded (likely MTU/DF path issue)")
    else:
        lines.append("DF probe: no size succeeded (expected, the host does not answer ping)")
    ok_sizes = [s for s, ok in ladder if ok]
    fail_sizes = [s for s, ok in ladder if not ok]
    lines.append(f"DF ladder OK: {ok_sizes or 'none'}")
    lines.append(f"DF ladder FAIL: {fail_sizes or 'none'}")

    if tcp_ok:
        lines.append(f"TCP handshake to {dest}:{port}: OK in {tcp_dt:.3f}s")
    else:
        lines.append(f"TCP handshake to {dest}:{port}: FAIL")

    if curl_t:
        lines.append(f"curl timing → {curl_t}")
    else:
        lines.append("curl timing: n/a")

    if trace_out:
        lines.append("\n--- tracepath/traceroute ---")
        lines.append(trace_out)

    # Heuristics
    probable_mtu = False
    reason = []
    # A host that ignores ping fails every DF size too, so the ladder only counts when a plain ping works
    if icmp_ok and (best_df is None or best_df < 1400):
        probable_mtu = True
        reason.append("DF probes fail at common sizes (below 1400)")

    if tcp_ok and (curl_t is None):
        probable_mtu = True
        reason.append("TCP handshake OK but TLS fetch failed (possible PMTUD blackhole)")

    # Verdict
    lines.append("\n=== Verdict ===")
    if probable_mtu:
        lines.append("Probable MTU/PMTUD issue.")
        lines.append("Evidence:")
        for r in reason:
            lines.append(f"  • {r}")
        lines.append("Remediation:")
        lines.append("  • Standardize link MTU to 1500 when possible, or")
        lines.append("  • Enable MSS clamping (for example 1360 to 1440) on the egress path/NAT, or")
        lines.append("  • Remove DF setting on problematic middleboxes")
        lines.append("Hints:")
        lines.append("  • Check the hop where tracepath shows a sharp MTU drop")
        lines.append("  • Compare wired vs Wi-Fi to isolate last-mile")
        exit_code = 2
    else:
        if not tcp_ok:
            lines.append("TCP connectivity failure (not a pure MTU problem). Investigate routing/firewall.")
            exit_code = 3
        else:
            lines.append("No clear MTU issue detected.")
            exit_code = 0

    return "\n".join(lines), exit_code

def main():
    ap = argparse.ArgumentParser(description="Diagnose MTU/PMTUD blackholes")
    ap.add_argument("--dest", required=True, help="Destination host (e.g., example.com)")
    ap.add_argument("--port", type=int, default=443, help="TCP port, default 443")
    args = ap.parse_args()

    # Quick DNS check
    try:
        socket.getaddrinfo(args.dest, args.port)
    except Exception:
        print("DNS resolution failed for destination", file=sys.stderr)
        sys.exit(4)

    icmp_ok = icmp_reachable(args.dest)
    best_df, ladder = df_ping(args.dest)
    tr = trace_path(args.dest)
    tcp_ok, tcp_dt = tcp_handshake(args.dest, args.port)
    curl_t = curl_tls_timing(args.dest, args.port)

    text, code = summarize(best_df, ladder, tcp_ok, tcp_dt, curl_t, tr, args.dest, args.port, icmp_ok)
    print(text)
    sys.exit(code)

if __name__ == "__main__":
    main()
