"""run_all.py - one command: system info -> primitives -> pipeline -> report.

    python run_all.py --quick      # smoke test, a few minutes
    python run_all.py              # full measurement run
"""
import argparse, multiprocessing as mp, os, time
from common import RESULTS, ensure_results, save_json, system_info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--no-slow", action="store_true", help="skip the slow SPHINCS+/SLH-DSA 's' variant")
    a = ap.parse_args()
    ensure_results()
    info = system_info()
    save_json(os.path.join(RESULTS, "system_info.json"), info)
    print("System:", info)
    import bench_primitives, pipeline, make_report
    t0 = time.time()
    n, b = (50, 2.0) if a.quick else (1000, 15.0)
    bench_primitives.run(n, b, not a.no_slow)
    runs, n_tx = (2, 40) if a.quick else (5, 200)
    pipeline.run_all(runs, n_tx, 20, not a.no_slow)
    make_report.main()
    print(f"\nAll done in {(time.time() - t0) / 60:.1f} min. Open results/REPORT.md")


if __name__ == "__main__":
    mp.freeze_support()
    main()
