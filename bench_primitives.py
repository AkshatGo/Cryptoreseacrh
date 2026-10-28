"""
bench_primitives.py - Layer 1: per-operation cost of every algorithm.

Output (all raw, nothing typed by hand):
  results/primitives_raw.csv    one row per timed call: algorithm, operation, ns
  results/primitives_sizes.csv  exact key / ciphertext / signature sizes
Tables are generated later by make_report.py from these files.
"""
import argparse, sys, time
import algos
from common import (MESSAGE, ensure_results, measure, raise_priority, system_info,
                    save_json, write_csv, RESULTS)
import os


def selftest_kem(kem):
    pk = kem.keygen()
    ct, ss1 = kem.encaps(pk)
    ss2 = kem.decaps(ct)
    assert ss1 == ss2, f"{kem.name}: shared secrets differ - benchmark would be meaningless"


def selftest_sig(sig):
    pk = sig.keygen()
    s = sig.sign(MESSAGE)
    assert sig.verify(pk, MESSAGE, s), f"{sig.name}: valid signature rejected"
    bad = bytearray(MESSAGE); bad[0] ^= 1
    assert not sig.verify(pk, bytes(bad), s), f"{sig.name}: tampered message accepted"


def run(n_max, budget_s, include_slow, only=None):
    ensure_results()
    raise_priority()
    raw, sizes = [], []

    def record(alg, family, op, samples):
        for i, ns in enumerate(samples):
            raw.append((alg, family, op, i, ns))
        med = sorted(samples)[len(samples) // 2] / 1e6
        print(f"    {op:<14} n={len(samples):<5} median={med:.4f} ms", flush=True)

    # ---------------------------------------------------------------- KEMs
    for label, make in algos.kem_catalog():
        if only and label not in only:
            continue
        print(f"[KEM] {label}", flush=True)
        kem = make()
        selftest_kem(kem)
        pk = kem.keygen()
        ct, _ = kem.encaps(pk)
        sz = kem.sizes()
        sizes.append((label, kem.family, "kem", sz["pk"], sz["sk"], sz["ct_or_sig"], len(ct), sz["ss"]))
        record(label, kem.family, "keygen", measure(kem.keygen, n_max, budget_s=budget_s))
        pk = kem.keygen()                                   # fresh matching key pair for the next ops
        ct, _ = kem.encaps(pk)
        record(label, kem.family, "encaps", measure(lambda: kem.encaps(pk), n_max, budget_s=budget_s))
        record(label, kem.family, "decaps", measure(lambda: kem.decaps(ct), n_max, budget_s=budget_s))

    # ---------------------------------------------------------------- SIGs
    for label, make in algos.sig_catalog(include_slow):
        if only and label not in only:
            continue
        print(f"[SIG] {label}", flush=True)
        sig = make()
        selftest_sig(sig)
        slow = algos.is_slow(label)
        nm = 60 if slow else n_max
        bud = max(budget_s, 25.0) if slow else budget_s
        warm = 3 if slow else 30
        record(label, sig.family, "keygen", measure(sig.keygen, nm, budget_s=bud, warmup=warm))
        pk = sig.keygen()
        # actual signature length (varies for ECDSA/Falcon): average over a few signatures
        lens = [len(sig.sign(MESSAGE)) for _ in range(20)]
        sz = sig.sizes()
        sizes.append((label, sig.family, "sig", sz["pk"], sz["sk"], sz["ct_or_sig"], sum(lens) / len(lens), 0))
        s = sig.sign(MESSAGE)
        record(label, sig.family, "sign", measure(lambda: sig.sign(MESSAGE), nm, budget_s=bud, warmup=warm))
        record(label, sig.family, "verify", measure(lambda: sig.verify(pk, MESSAGE, s), nm, budget_s=bud, warmup=warm))

    write_csv(os.path.join(RESULTS, "primitives_raw.csv"),
              ["algorithm", "family", "operation", "sample", "ns"], raw)
    write_csv(os.path.join(RESULTS, "primitives_sizes.csv"),
              ["algorithm", "family", "kind", "public_key_B", "secret_key_B",
               "ct_or_sig_max_B", "ct_or_sig_actual_mean_B", "shared_secret_B"], sizes)
    print(f"\nSaved {len(raw)} raw samples to results/primitives_raw.csv")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smoke test: few samples")
    ap.add_argument("--no-slow", action="store_true", help="skip SPHINCS+/SLH-DSA 's' variants")
    ap.add_argument("--only", nargs="*", help="restrict to these algorithm names")
    a = ap.parse_args()
    n, b = (50, 2.0) if a.quick else (1000, 15.0)
    t0 = time.time()
    run(n, b, not a.no_slow, a.only)
    print(f"Done in {time.time() - t0:.0f}s")
