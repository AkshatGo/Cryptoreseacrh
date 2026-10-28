"""common.py - system info, timing loop, statistics, CSV helpers."""
import csv, gc, json, math, os, platform, statistics, subprocess, sys, time

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
MESSAGE = bytes((i * 7 + 3) % 256 for i in range(100))      # fixed 100-byte message


def ensure_results():
    os.makedirs(RESULTS, exist_ok=True)
    return RESULTS


# ---------------------------------------------------------------- system info
def _cpu_name():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Processor).Name"], text=True, timeout=20)
            return out.strip().splitlines()[0]
        if platform.system() == "Linux":
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        if platform.system() == "Darwin":
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def system_info():
    info = {"cpu": _cpu_name(), "os": f"{platform.system()} {platform.release()} ({platform.version()})",
            "machine": platform.machine(), "python": sys.version.split()[0],
            "logical_cpus": os.cpu_count()}
    try:
        import psutil
        info["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
        info["physical_cores"] = psutil.cpu_count(logical=False)
        freq = psutil.cpu_freq()
        if freq:
            info["cpu_mhz_reported"] = round(freq.current)
        b = psutil.sensors_battery()
        info["on_ac_power"] = None if b is None else bool(b.power_plugged)
    except Exception:
        pass
    try:
        import cryptography
        info["cryptography_lib"] = cryptography.__version__
    except Exception:
        pass
    try:
        from algos import HAVE_OQS, OQS_ERROR
        import algos
        if HAVE_OQS:
            info["liboqs"] = algos.oqs.oqs_version()
            info["liboqs_python"] = algos.oqs.oqs_python_version()
        else:
            info["liboqs"] = f"NOT AVAILABLE: {OQS_ERROR}"
    except Exception as e:
        info["liboqs"] = f"error: {e}"
    return info


def raise_priority():
    """Best-effort: reduce scheduler noise. Silent if not permitted."""
    try:
        import psutil
        p = psutil.Process()
        if platform.system() == "Windows":
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            p.nice(-5)
    except Exception:
        pass


# --------------------------------------------------------------------- timing
def measure(fn, n_max=1000, n_min=20, budget_s=15.0, warmup=30, warmup_budget_s=3.0):
    """
    Call fn() repeatedly, timing EACH call with perf_counter_ns.
    * warm-up calls are run first and discarded
    * stops at n_max samples, or when budget_s is exceeded (but never below n_min)
    * garbage collection is disabled while timing
    Returns a list of nanosecond samples.
    """
    t_end = time.perf_counter() + warmup_budget_s
    for _ in range(warmup):
        fn()
        if time.perf_counter() > t_end:
            break
    gc.collect()
    gc.disable()
    samples = []
    start = time.perf_counter()
    try:
        while len(samples) < n_max:
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
            if len(samples) >= n_min and (time.perf_counter() - start) > budget_s:
                break
    finally:
        gc.enable()
    return samples


# ----------------------------------------------------------------- statistics
def pct(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    k = (len(sorted_vals) - 1) * q
    f, c = math.floor(k), math.ceil(k)
    return sorted_vals[int(k)] if f == c else sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def stats(samples):
    s = sorted(samples)
    n = len(s)
    mean = statistics.fmean(s)
    sd = statistics.stdev(s) if n > 1 else 0.0
    return {"n": n, "median": pct(s, .5), "mean": mean, "stdev": sd,
            "p95": pct(s, .95), "min": s[0], "max": s[-1],
            "ci95_mean": 1.96 * sd / math.sqrt(n) if n > 1 else 0.0}


# ------------------------------------------------------------------------ io
def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def save_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
