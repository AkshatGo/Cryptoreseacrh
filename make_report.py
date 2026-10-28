"""
make_report.py - builds ALL tables from the raw CSV logs. Nothing is typed by hand.

Reads:  results/primitives_raw.csv, primitives_sizes.csv, pipeline_runs.csv, pipeline_tx.csv,
        pipeline_blocks.csv, system_info.json
Writes: results/REPORT.md, table_*.csv, charts/*.png (if matplotlib is installed)
"""
import collections, json, os, statistics
from common import RESULTS, read_csv, stats, write_csv

# Pilot values = the numbers from our FIRST (uncontrolled) run, kept only for the audit table.
PILOT_MS = {"ECDSA sign": 0.0215, "ECDSA verify": 0.0533, "ML-DSA-44 sign": 1.5552, "ML-DSA-44 verify": 0.3271}


def p(name):
    return os.path.join(RESULTS, name)


def fmt_ms(ns):
    ms = ns / 1e6
    return f"{ms:.1f}" if ms >= 100 else (f"{ms:.2f}" if ms >= 1 else f"{ms:.4f}")


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ----------------------------------------------------------------- primitives
def primitives_section(lines, claims_ctx):
    if not os.path.exists(p("primitives_raw.csv")):
        lines.append("_No primitive results found (run bench_primitives.py)._")
        return
    raw = read_csv(p("primitives_raw.csv"))
    sizes = {r["algorithm"]: r for r in read_csv(p("primitives_sizes.csv"))}
    data, order = collections.defaultdict(list), []
    for r in raw:
        if r["algorithm"] not in order:
            order.append(r["algorithm"])
        data[(r["algorithm"], r["operation"])].append(int(r["ns"]))
    st = {k: stats(v) for k, v in data.items()}
    claims_ctx["st"], claims_ctx["sizes"], claims_ctx["order"] = st, sizes, order

    rows, full = [], []
    for alg in order:
        sz = sizes[alg]
        ops = ("keygen", "encaps", "decaps") if sz["kind"] == "kem" else ("keygen", "sign", "verify")
        cells = [f"{fmt_ms(st[(alg, o)]['median'])} [{fmt_ms(st[(alg, o)]['p95'])}]" for o in ops]
        nmin = min(st[(alg, o)]["n"] for o in ops)
        sig_actual = float(sz["ct_or_sig_actual_mean_B"])
        rows.append((alg, sz["family"], *cells, sz["public_key_B"], sz["secret_key_B"],
                     f"{sig_actual:.0f}" if sz["kind"] == "sig" else sz["ct_or_sig_max_B"], nmin))
        for o in ops:
            s = st[(alg, o)]
            full.append((alg, sz["family"], o, s["n"], *(round(s[k] / 1e6, 6) for k in
                         ("median", "mean", "stdev", "p95", "min", "max", "ci95_mean"))))
    header = ["Algorithm", "Family", "Keygen ms", "Sign / Encaps ms", "Verify / Decaps ms",
              "Public key B", "Secret key B", "Signature / Ciphertext B", "min n"]
    lines.append("### Table A - Cryptographic primitives (median [95th percentile], milliseconds)\n")
    lines.append(md_table(header, rows))
    lines.append("\nKEM rows use Encaps/Decaps; signature rows use Sign/Verify. For ECDH, 'encaps' is the initiator step "
                 "(ephemeral key + shared secret) and 'decaps' is the responder step. Every operation takes and returns "
                 "raw bytes, so parsing cost is included for classical and post-quantum alike.\n")
    write_csv(p("table_A.csv"), header, rows)
    write_csv(p("table_A_full_stats.csv"),
              ["algorithm", "family", "operation", "n", "median_ms", "mean_ms", "stdev_ms", "p95_ms", "min_ms", "max_ms",
               "ci95_of_mean_ms"], full)

    # Audit table: pilot vs controlled
    def med(a, o):
        return st[(a, o)]["median"] / 1e6 if (a, o) in st else None
    cs, cv, ps, pv = med("ECDSA-P256", "sign"), med("ECDSA-P256", "verify"), med("ML-DSA-44", "sign"), med("ML-DSA-44", "verify")
    if None not in (cs, cv, ps, pv):
        rows_d = [("Signing: ML-DSA-44 vs ECDSA", f"{PILOT_MS['ML-DSA-44 sign']} vs {PILOT_MS['ECDSA sign']} ms",
                   f"{PILOT_MS['ML-DSA-44 sign'] / PILOT_MS['ECDSA sign']:.1f}x",
                   f"{ps:.4f} vs {cs:.4f} ms", f"{ps / cs:.1f}x"),
                  ("Verification: ML-DSA-44 vs ECDSA", f"{PILOT_MS['ML-DSA-44 verify']} vs {PILOT_MS['ECDSA verify']} ms",
                   f"{PILOT_MS['ML-DSA-44 verify'] / PILOT_MS['ECDSA verify']:.1f}x",
                   f"{pv:.4f} vs {cv:.4f} ms", f"{pv / cv:.1f}x")]
        lines.append("### Table D - Effect of correcting the measurement method (pilot vs controlled)\n")
        lines.append(md_table(["Comparison", "Pilot (first run)", "Pilot ratio", "Controlled (this run)", "Controlled ratio"], rows_d))
        lines.append("\nThe pilot timed key generation inside the post-quantum signing loop and re-created the library object "
                     "on every verify, so its ratios overstated the post-quantum cost. The controlled run times each "
                     "operation separately with setup outside the loop.\n")


# ------------------------------------------------------------------- pipeline
def pipeline_section(lines, claims_ctx):
    if not os.path.exists(p("pipeline_runs.csv")):
        lines.append("_No pipeline results found (run pipeline.py)._")
        return
    runs, tx, blk = read_csv(p("pipeline_runs.csv")), read_csv(p("pipeline_tx.csv")), read_csv(p("pipeline_blocks.csv"))
    cfgs = []
    for r in runs:
        if r["config"] not in cfgs:
            cfgs.append(r["config"])
    g = lambda rows, c: [r for r in rows if r["config"] == c]
    rows1, rows2, share = [], [], {}
    for c in cfgs:
        R, T, B = g(runs, c), g(tx, c), g(blk, c)
        txb = statistics.fmean(int(t["tx_bytes"]) for t in T)
        wire = statistics.fmean(int(t["wire_bytes"]) for t in T)
        blkb = statistics.fmean(int(b["block_bytes"]) for b in B)
        sh = 100 * sum(int(b["sig_bytes_in_block"]) for b in B) / sum(int(b["block_bytes"]) for b in B)
        share[c] = sh
        devpk = int(R[0]["dev_sig_pk_B"])
        ok = all(int(r["chain_valid"]) and int(r["tamper_detected"]) and int(r["bad_sigs"]) == 0 for r in R)
        rows1.append((c, R[0]["block_size"], f"{txb:.0f}", f"{txb + devpk:.0f}", f"{wire:.0f}", f"{blkb:.0f}",
                      f"{sh:.1f}%", R[0]["session_setup_bytes"], "yes" if ok else "NO"))
        thr = [int(r["n_tx"]) / (int(r["device_wall_ns"]) / 1e9) for r in R]
        sign = stats([int(t["sign_ns"]) for t in T]); ver = stats([int(t["verify_ns"]) for t in T])
        e2e = stats([int(t["e2e_ns"]) for t in T]); seal = stats([int(b["build_ns"]) for b in B])
        cv = stats([int(r["chain_verify_ns"]) for r in R]); hs = stats([int(r["handshake_ns"]) for r in R])
        nver = int(R[0]["n_tx"]) + int(R[0]["n_blocks"])
        rows2.append((c, fmt_ms(sign["median"]), fmt_ms(ver["median"]), fmt_ms(seal["median"]), fmt_ms(e2e["median"]),
                      f"{statistics.median(thr):.0f} [{min(thr):.0f}-{max(thr):.0f}]",
                      f"{fmt_ms(cv['median'])} ({nver} sigs)", fmt_ms(hs["median"]), len(R)))
    h1 = ["Configuration", "tx / block", "Tx size B", "Tx size incl. public key B (derived)", "Tx on wire B (encrypted)",
          "Block size B", "Signature share of block", "Session setup B (pk + ct + device pk)", "Chain valid + tamper caught"]
    h2 = ["Configuration", "Device sign ms", "Gateway verify ms", "Block seal ms", "Sign-to-ack latency ms",
          "Throughput tx/s median [min-max]", "Full chain verify ms", "Handshake ms", "runs"]
    lines.append("### Table B1 - Pipeline sizes (bytes, measured)\n")
    lines.append(md_table(h1, rows1))
    lines.append("\n'Tx size incl. public key' is simple arithmetic (measured tx size + measured public-key size) showing the "
                 "cost if every transaction carried its public key, as Bitcoin-style designs do.\n")
    lines.append("### Table B2 - Pipeline timing (median over all samples; device and gateway are separate processes)\n")
    lines.append(md_table(h2, rows2))
    lines.append("\nThroughput is closed-loop (the device waits for an acknowledgement per transaction), over loopback TCP, "
                 "so it reflects compute plus local IPC, not real network latency.\n")
    write_csv(p("table_B1.csv"), h1, rows1)
    write_csv(p("table_B2.csv"), h2, rows2)
    claims_ctx["share"] = share


# --------------------------------------------------------------------- claims
def claims_section(lines, ctx):
    st, sizes, order = ctx.get("st"), ctx.get("sizes"), ctx.get("order", [])
    if not st:
        return
    find = lambda frag: next((a for a in order if frag in a.upper()), None)
    mld, fal, slh = "ML-DSA-44" if "ML-DSA-44" in order else None, "Falcon-512" if "Falcon-512" in order else None, find("128F")
    med = lambda a, o: st[(a, o)]["median"] / 1e6
    rows = []

    def add(claim, ref, measured, verdict):
        rows.append((claim, ref, measured, verdict))

    def three(op):
        return {a: med(a, op) for a in (mld, fal, slh) if a}

    if mld and fal and slh:
        s, v, k = three("sign"), three("verify"), three("keygen")
        fastest = lambda d: min(d, key=d.get)
        slowest = lambda d: max(d, key=d.get)
        txt = lambda d: ", ".join(f"{a} {x:.4f}" for a, x in d.items())
        add("Dilithium has the fastest signing of the three NIST signatures", "Sec. VIII-J",
            f"sign ms: {txt(s)}", "CONSISTENT" if fastest(s) == mld else "NOT CONSISTENT")
        add("FALCON has the fastest verification", "Sec. VII / VIII-J",
            f"verify ms: {txt(v)}", "CONSISTENT" if fastest(v) == fal else "NOT CONSISTENT")
        add("FALCON has the slowest signing", "Sec. VII",
            f"sign ms: {txt(s)}", "CONSISTENT" if slowest(s) == fal else "NOT CONSISTENT")
        add("FALCON has the slowest key generation", "Sec. III-C3",
            f"keygen ms: {txt(k)}", "CONSISTENT" if slowest(k) == fal else "NOT CONSISTENT")
        sg = {a: float(sizes[a]["ct_or_sig_actual_mean_B"]) for a in (mld, fal, slh)}
        pk = {a: int(sizes[a]["public_key_B"]) for a in (mld, fal, slh)}
        add("SLH-DSA-SHAKE-128F has the largest signatures; FALCON the smallest", "Sec. III-C2/3",
            "signature B: " + ", ".join(f"{a} {x:.0f}" for a, x in sg.items()),
            "CONSISTENT" if max(sg, key=sg.get) == slh and min(sg, key=sg.get) == fal else "NOT CONSISTENT")
        add("SLH-DSA-SHAKE-128F has the smallest public keys (< 1 KB); Dilithium keys are larger", "Sec. III-C2/3",
            "public key B: " + ", ".join(f"{a} {x}" for a, x in pk.items()),
            "CONSISTENT" if min(pk, key=pk.get) == slh and pk[mld] > pk[slh] else "NOT CONSISTENT")
        add("Lattice-based (ML-DSA) is faster than hash-based (SLH-DSA-SHAKE-128F) for signing and verification", "Sec. IV",
            f"sign {s[mld]:.4f} vs {s[slh]:.4f} ms; verify {v[mld]:.4f} vs {v[slh]:.4f} ms",
            "CONSISTENT" if s[mld] < s[slh] and v[mld] < v[slh] else "NOT CONSISTENT")
    ks = [a for a in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024") if a in order]
    if len(ks) == 3:
        enc = [med(a, "encaps") for a in ks]
        pks = [int(sizes[a]["public_key_B"]) for a in ks]
        ok = enc[0] < enc[1] < enc[2] and pks[0] < pks[1] < pks[2]
        add("Kyber: higher security level means larger keys and slower operations", "Sec. III-B1",
            "encaps ms: " + " < ".join(f"{x:.4f}" for x in enc) + "; pk B: " + " < ".join(map(str, pks)),
            "CONSISTENT" if ok else "NOT CONSISTENT")
    share = ctx.get("share", {})
    if "classical" in share and len(share) > 1:
        pq = {c: v for c, v in share.items() if c != "classical"}
        add("Post-quantum signatures take a larger share of block space (scalability concern)", "Sec. VIII-H",
            f"signature share of block: classical {share['classical']:.1f}% vs post-quantum " +
            ", ".join(f"{v:.0f}%" for v in pq.values()),
            "CONSISTENT" if all(v > share["classical"] for v in pq.values()) else "NOT CONSISTENT")
    if rows:
        lines.append("### Table C - Does the base paper's reported behaviour hold on our hardware?\n")
        lines.append(md_table(["Claim from the base paper", "Where", "What we measured", "Verdict"], rows))
        lines.append("\nThe paper's figures come from other studies on other hardware (mostly ARM Cortex-M), so a 'NOT CONSISTENT' "
                     "result is a legitimate finding about x86 behaviour, not an error. Memory-related claims are not tested here.\n")
        write_csv(p("table_C.csv"), ["claim", "where", "measured", "verdict"], rows)


# --------------------------------------------------------------------- charts
def charts(ctx):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    st, sizes, order = ctx.get("st"), ctx.get("sizes"), ctx.get("order", [])
    if not st:
        return
    os.makedirs(p("charts"), exist_ok=True)
    sigs = [a for a in order if sizes[a]["kind"] == "sig"]
    x = range(len(sigs))
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - 0.2 for i in x], [st[(a, "sign")]["median"] / 1e6 for a in sigs], 0.4, label="sign")
    ax.bar([i + 0.2 for i in x], [st[(a, "verify")]["median"] / 1e6 for a in sigs], 0.4, label="verify")
    ax.set_yscale("log"); ax.set_ylabel("median time (ms, log scale)")
    ax.set_xticks(list(x)); ax.set_xticklabels(sigs, rotation=30, ha="right"); ax.legend(); ax.set_title("Signature operations")
    fig.tight_layout(); fig.savefig(p("charts/signature_time.png"), dpi=150); plt.close(fig)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - 0.2 for i in x], [int(sizes[a]["public_key_B"]) for a in sigs], 0.4, label="public key")
    ax.bar([i + 0.2 for i in x], [float(sizes[a]["ct_or_sig_actual_mean_B"]) for a in sigs], 0.4, label="signature")
    ax.set_yscale("log"); ax.set_ylabel("bytes (log scale)")
    ax.set_xticks(list(x)); ax.set_xticklabels(sigs, rotation=30, ha="right"); ax.legend(); ax.set_title("Key and signature sizes")
    fig.tight_layout(); fig.savefig(p("charts/signature_size.png"), dpi=150); plt.close(fig)


def main():
    lines, ctx = [], {}
    lines.append("# Post-Quantum vs Classical Cryptography - Measured Results\n")
    si = p("system_info.json")
    if os.path.exists(si):
        info = json.load(open(si))
        lines.append("## Test platform (recorded automatically)\n")
        lines.append(md_table(["Item", "Value"], [(k, v) for k, v in info.items()]))
        lines.append("")
    lines.append("## Results\n")
    primitives_section(lines, ctx)
    pipeline_section(lines, ctx)
    claims_section(lines, ctx)
    lines.append("## What these results can and cannot claim\n")
    lines.append("- Real measurements on one general-purpose device, with one method applied identically to every algorithm.\n"
                 "- NOT absolute numbers for constrained IoT hardware, and NOT real network latency (loopback only).\n"
                 "- Peak memory is not reported: Python cannot measure native-library memory reliably. Exact key and "
                 "signature sizes are reported instead; a RAM-capped or Raspberry Pi test is the next step.\n"
                 "- No Proof-of-Work: blocks are sealed by an authority signature, as lightweight IoT chains do.\n")
    open(p("REPORT.md"), "w", encoding="utf-8").write("\n".join(lines))
    charts(ctx)
    print("Wrote results/REPORT.md and table_*.csv")


if __name__ == "__main__":
    main()
