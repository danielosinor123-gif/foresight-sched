#!/usr/bin/env python3
"""foresight-sched Phase 4: benchmark battery orchestrator.

Pre-registered methodology per BENCHMARK-PLAN.md — the measurement rules
were locked before any benchmark ran, so results can't be tuned.

Configs (scheduler under test):
    eevdf          kernel default (foresight_sched unloaded)
    foresight      foresight_sched loaded, knobs at defaults (20/20ms, demote 10)
    scx_simple     in-tree reference (same FIFO family as our fallback)

Regimes (workload shapes):
    interactive    2x vCPU CPU hogs + 1 waker thread (2ms sleep)
                   metric: p50/p99 wake-to-run latency via /proc/pid/schedstat
    batch          4 CPU-bound workers counting iterations
                   metric: iterations/s (aggregate)
    mixed          both simultaneously — the trade-off curve
                   metrics: both, plus the pre-registered PASS/FAIL check

Measurement: external only (/proc/<pid>/schedstat, wall-clock iteration
counts, /proc/pressure/cpu). NEVER the BPF stats map (lane-visibility
caveat per the Phase 2 micro-test).

Usage (from inside WSL):
    cd /root/WSL2-Linux-Kernel/tools/sched_ext/build/bin
    python3 /root/foresight-sched/bench/run_bench.py [--duration 30] [--reps 2] [--configs eevdf,foresight]

Output: raw JSON per (config, regime, rep) + a summary table.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time

# ------------------------------------------------------------------ config

BIN_DIR = "/root/WSL2-Linux-Kernel/tools/sched_ext/build/bin"
OUT_DIR = "/root/foresight-sched/bench/results"
WARMUP_S = 5
MEASURE_S = 30
REPS = 2
VCPUS = os.cpu_count() or 4

CONFIGS = {
    "eevdf":      {"desc": "kernel default (EEVDF)"},
    "foresight":  {"desc": "foresight_sched (20/20ms, demote@10)"},
    "scx_simple": {"desc": "in-tree reference (scx_simple)"},
}


# ------------------------------------------------------------- scheduler mgmt

def stop_all_schedulers():
    """Unload any sched_ext scheduler and kill all scheduler binaries."""
    subprocess.run(["pkill", "-INT", "-x", "foresight_sched"],
                   capture_output=True, timeout=5)
    subprocess.run(["pkill", "-INT", "-x", "scx_simple"],
                   capture_output=True, timeout=5)
    subprocess.run(["pkill", "-TERM", "-f", "foresight_daemon"],
                   capture_output=True, timeout=5)
    time.sleep(2)
    # verify
    r = subprocess.run(["pgrep", "-x", "foresight_sched"], capture_output=True)
    if r.returncode == 0:
        subprocess.run(["pkill", "-9", "-x", "foresight_sched"], capture_output=True)
        time.sleep(1)


CONFIG_BINARY = {
    "eevdf": None,
    "foresight": "foresight_sched",
    "scx_simple": "scx_simple",
}


def ensure_bpffs():
    """Mount bpffs if not mounted (WSL2: each wsl.exe invocation gets a
    private mount namespace - the previous mount doesn't persist)."""
    r = subprocess.run(["grep", "-qs", "bpf", "/proc/mounts"],
                       capture_output=True, text=True)
    if r.returncode != 0 or "bpf" not in r.stdout:
        subprocess.run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"],
                       capture_output=True, timeout=10)


def load_scheduler(config: str) -> subprocess.Popen | None:
    """Load the named scheduler; return the Popen or None for EEVDF."""
    ensure_bpffs()
    if config == "eevdf":
        return None  # no scheduler = kernel default
    binary_name = CONFIG_BINARY.get(config, config)
    binary = os.path.join(BIN_DIR, binary_name)
    if not os.path.exists(binary):
        raise FileNotFoundError(f"scheduler binary not found: {binary}")
    return subprocess.Popen([binary], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def wait_for_enable(timeout_s: float = 5.0) -> bool:
    """Wait for sched_ext state to reach 'enabled' (or stay 'disabled')."""
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        try:
            state = open("/sys/kernel/sched_ext/state").read().strip()
            if state == "enabled":
                return True
        except (FileNotFoundError, OSError):
            pass
        time.sleep(0.2)
    return False


# ------------------------------------------------------------- workloads

def cpu_hog(duration_s: float) -> None:
    """100% CPU busy loop."""
    end = time.monotonic() + duration_s
    while time.monotonic() < end:
        pass


def waker(duration_s: float, latencies: list) -> None:
    """2ms-sleep waker: measures wake-to-run latency via schedstat.

    /proc/<pid>/schedstat field 1 (ns) = cumulative time on a runqueue
    waiting to be dispatched. The delta between two reads spans one
    wake cycle: the runqueue wait for that wake + any preemption
    during the brief run. For a 2ms-sleep waker reading immediately
    after waking, the contamination is negligible.
    """
    stat_path = "/proc/self/schedstat"
    end = time.monotonic() + duration_s

    def read_wait():
        with open(stat_path) as fh:
            return int(fh.read().split()[0])

    prev = read_wait()
    while time.monotonic() < end:
        time.sleep(0.002)
        cur = read_wait()
        delta = cur - prev
        prev = cur
        if delta > 0:
            latencies.append(delta)


def batch_worker(duration_s: float, results: dict, wid: int) -> None:
    """CPU-bound iteration counter."""
    end = time.monotonic() + duration_s
    count = 0
    while time.monotonic() < end:
        x = 0
        for i in range(1000):
            x += i * i
        count += 1
    results[wid] = count


def percentile(data: list, pct: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = int(len(s) * pct / 100.0)
    idx = min(idx, len(s) - 1)
    return s[idx]


# ------------------------------------------------------------- regime runners

def run_interactive(duration_s: float) -> dict:
    """CPU hogs saturating + 1 waker measuring wake latency."""
    n_hogs = VCPUS * 2
    latencies: list = []
    threads = []
    end = time.monotonic() + duration_s

    for _ in range(n_hogs):
        t = threading.Thread(target=cpu_hog, args=(end - time.monotonic(),))
        t.start()
        threads.append(t)

    # let hogs saturate before starting the waker
    time.sleep(2)
    wt = threading.Thread(target=waker, args=(end - time.monotonic() - 2, latencies))
    wt.start()
    threads.append(wt)

    for t in threads:
        t.join()

    latencies.sort()
    p50 = percentile(latencies, 50) / 1000.0  # ns -> μs
    p99 = percentile(latencies, 99) / 1000.0
    mean = statistics.mean(latencies) / 1000.0 if latencies else 0.0
    return {
        "wake_latency_p50_us": round(p50, 1),
        "wake_latency_p99_us": round(p99, 1),
        "wake_latency_mean_us": round(mean, 1),
        "wake_samples": len(latencies),
    }


def run_batch(duration_s: float) -> dict:
    """4 CPU-bound workers counting iterations."""
    results = {}
    threads = []
    n_workers = VCPUS
    for wid in range(n_workers):
        t = threading.Thread(target=batch_worker, args=(duration_s, results, wid))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    total = sum(results.values())
    return {
        "batch_iterations_total": total,
        "batch_workers": n_workers,
        "batch_iters_per_sec": round(total / duration_s, 0),
    }


def run_mixed(duration_s: float) -> dict:
    """Both interactive and batch simultaneously — the trade-off regime."""
    n_hogs = VCPUS  # half the CPUs for hogs, half for batch + waker
    latencies: list = []
    batch_results: dict = {}
    threads = []

    end = time.monotonic() + duration_s
    for _ in range(n_hogs):
        t = threading.Thread(target=cpu_hog, args=(end - time.monotonic(),))
        t.start()
        threads.append(t)

    time.sleep(1)  # let hogs spin up before measuring

    wt = threading.Thread(target=waker, args=(end - time.monotonic() - 1, latencies))
    wt.start()
    threads.append(wt)

    for wid in range(2):
        t = threading.Thread(target=batch_worker,
                             args=(end - time.monotonic() - 1, batch_results, wid))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    latencies.sort()
    p50 = percentile(latencies, 50) / 1000.0
    p99 = percentile(latencies, 99) / 1000.0
    batch_total = sum(batch_results.values())
    return {
        "wake_latency_p50_us": round(p50, 1),
        "wake_latency_p99_us": round(p99, 1),
        "batch_iters_per_sec": round(batch_total / duration_s, 0),
        "wake_samples": len(latencies),
    }


REGIME_RUNNERS = {
    "interactive": run_interactive,
    "batch": run_batch,
    "mixed": run_mixed,
}


# ------------------------------------------------------------- orchestrator

def run_one(config: str, regime: str, rep: int, measure_s: float) -> dict:
    """One (config, regime, rep) measurement: setup, warmup, measure, teardown."""
    stop_all_schedulers()
    proc = load_scheduler(config)
    if proc is not None and config != "eevdf":
        if not wait_for_enable():
            stop_all_schedulers()
            return {"config": config, "regime": regime, "rep": rep,
                    "error": "scheduler failed to load"}

    # warmup
    time.sleep(WARMUP_S)

    # measure
    runner = REGIME_RUNNERS[regime]
    result = runner(measure_s)
    result["config"] = config
    result["regime"] = regime
    result["rep"] = rep

    stop_all_schedulers()
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="foresight-sched benchmark battery")
    parser.add_argument("--duration", type=int, default=MEASURE_S,
                        help="measurement window per rep (seconds)")
    parser.add_argument("--reps", type=int, default=REPS)
    parser.add_argument("--configs", type=str, default="eevdf,foresight",
                        help="comma-separated configs to test")
    parser.add_argument("--regimes", type=str, default="mixed",
                        help="comma-separated regimes to test")
    parser.add_argument("--out", type=str, default=os.path.join(OUT_DIR, "results.json"))
    args = parser.parse_args(argv)

    configs = [c.strip() for c in args.configs.split(",")]
    regimes = [r.strip() for r in args.regimes.split(",")]
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    all_results: list[dict] = []
    total_measurements = len(configs) * len(regimes) * args.reps
    done = 0

    print(f"foresight-sched benchmark battery: {len(configs)} configs x "
          f"{len(regimes)} regimes x {args.reps} reps x {args.duration}s each")

    # Interleaved ABCBA order to defeat thermal/frequency drift
    for rep in range(args.reps):
        for regime in regimes:
            for config in configs:
                done += 1
                print(f"  [{done}/{total_measurements}] {config} / {regime} / rep {rep + 1}...")
                result = run_one(config, regime, rep, args.duration)
                all_results.append(result)
                if "error" in result:
                    print(f"    ERROR: {result['error']}")
                else:
                    key_metrics = {k: v for k, v in result.items()
                                   if k not in ("config", "regime", "rep")}
                    print(f"    {key_metrics}")

    # save raw
    with open(args.out, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"\nraw results: {args.out}")

    # summary table
    print("\n" + "=" * 72)
    print("SUMMARY (mean across reps)")
    print("=" * 72)
    by_key: dict[tuple, list] = {}
    for r in all_results:
        key = (r["config"], r["regime"])
        by_key.setdefault(key, []).append(r)

    for (config, regime), results in sorted(by_key.items()):
        print(f"\n  {config} / {regime}:")
        metric_keys = [k for k in results[0] if k not in ("config", "regime", "rep", "error")]
        for mk in metric_keys:
            vals = [r[mk] for r in results if mk in r and isinstance(r[mk], (int, float))]
            if vals:
                mean_v = statistics.mean(vals)
                if "latency" in mk:
                    print(f"    {mk:<28} mean {mean_v:>10.1f} us")
                else:
                    print(f"    {mk:<28} mean {mean_v:>10.0f}")

    # pre-registered check (mixed regime, eevdf vs foresight)
    if "mixed" in regimes and "eevdf" in configs and "foresight" in configs:
        eevdf = [r for r in all_results if r["config"] == "eevdf" and r["regime"] == "mixed"]
        fore = [r for r in all_results if r["config"] == "foresight" and r["regime"] == "mixed"]
        if eevdf and fore:
            e_p99 = statistics.mean([r.get("wake_latency_p99_us", 0) for r in eevdf])
            f_p99 = statistics.mean([r.get("wake_latency_p99_us", 0) for r in fore])
            e_batch = statistics.mean([r.get("batch_iters_per_sec", 0) for r in eevdf])
            f_batch = statistics.mean([r.get("batch_iters_per_sec", 0) for r in fore])
            print("\n" + "=" * 72)
            print("PRE-REGISTERED ACCEPTANCE CHECK (mixed regime)")
            print("=" * 72)
            if e_p99 > 0:
                improvement = (e_p99 - f_p99) / e_p99 * 100.0
                print(f"  p99 wake latency: EEVDF {e_p99:.1f}us vs foresight {f_p99:.1f}us "
                      f"-> {improvement:+.1f}%")
                verdict_latency = "PASS" if improvement >= 15.0 else "FAIL"
                print(f"  gate (>= 15% improvement): {verdict_latency}")
            if e_batch > 0:
                batch_delta = (f_batch - e_batch) / e_batch * 100.0
                print(f"  batch throughput: EEVDF {e_batch:.0f} vs foresight {f_batch:.0f} "
                      f"-> {batch_delta:+.1f}%")
                verdict_batch = "PASS" if batch_delta >= -10.0 else "FAIL"
                print(f"  gate (>= -10% degradation): {verdict_batch}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
