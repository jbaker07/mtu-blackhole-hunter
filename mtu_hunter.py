import argparse, subprocess, sys, shutil, socket, time, re

SIZES = list(range(1472, 1199, -40))  # DF ladder for IPv4 (payload sizes)

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def have(cmd):
    return shutil.which(cmd) is not None

def df_ping(dest):
    """Return first working DF size, and per-size results."""
    results = []
    best = None
    for s in SIZES:
        if have("ping"):
            # Linux: -M do -s SIZE ; macOS: -D (no strict DF), fallback to Linux style if available
            cmd = ["ping", "-c", "1", "-W", "1"]
            if sys.platform == "darwin":
                # macOS lacks -M do; try -D (set DF) and -s SIZE with inet6 disabled by default
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
    if have("tracepath"):
        rc, out, _ = run(["tracepath", "-n", dest])
        return out
    elif have("traceroute"):
        # macOS fallback; not the same as tracepath but provides hop context
        rc, out, _ = run(["traceroute", "-n", "-F", dest])
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
    rc, out, _ = run([
        "curl","-sS","-o","/dev/null","-w",
        "lookup:%{time_namelookup} connect:%{time_connect} tls:%{time_appconnect} ttfb:%{time_starttransfer} total:%{time_total}",
        url
    ])
    return out if rc == 0 else None

def summarize(best_df, ladder, tcp_ok, tcp_dt, curl_t, trace_out, dest, port):
    lines = []
    lines.append("=== MTU / PMTUD Blackhole Hunter ===")
    if best_df is not None:
        lines.append(f"DF probe: first success at payload {best_df} bytes")
    else:
        lines.append("DF probe: no size succeeded (likely MTU/DF path issue)")
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
    if best_df is None or best_df < 1400:
        probable_mtu = True
        reason.append("DF probes fail at common sizes (below 1400)")

    if tcp_ok and (curl_t is None):
        probable_mtu = True
        reason.append("TCP handshake OK but TLS fetch failed (possible PMTUD blackhole)")

    # Verdict
    lines.append("\n=== Verdict ===")
    if probable_mtu:
        lines.append("Probable MTU/PMTUD issue.")
        lines.append("Remediation:")
        lines.append("  • Standardize link MTU to 1500 when possible, or")
        lines.append("  • Enable MSS clamping (e.g., 1360–1440) on the egress path/NAT, or")
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

    best_df, ladder = df_ping(args.dest)
    tr = trace_path(args.dest)
    tcp_ok, tcp_dt = tcp_handshake(args.dest, args.port)
    curl_t = curl_tls_timing(args.dest, args.port)

    text, code = summarize(best_df, ladder, tcp_ok, tcp_dt, curl_t, tr, args.dest, args.port)
    print(text)
    sys.exit(code)

if __name__ == "__main__":
    main()
