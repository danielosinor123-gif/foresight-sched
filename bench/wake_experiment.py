#!/usr/bin/env python3
"""Phase 4 focused experiment: does the behavior demotion improve wake
latency over time?

Setup: 3 CPU-bound spinners with comm 'bash' (classified INTERACTIVE by
the daemon) + 1 waker thread (also 'bash' comm, sleeping 2ms). The
kernel should demote the hogs after ~10 full slices (~200ms), which
should improve the waker's runqueue wait in the seconds after.

Timeline: run for 60s, sample schedstat every 5s, and compare the
latency in the first 20s (before demotion stabilizes) vs the last 20s
(after demotion). Also run the same experiment under EEVDF (no
scheduler) as the baseline.

Usage (from inside WSL):
    python3 /root/foresight-sched/bench/wake_experiment.py [--scheduler eevdf|foresight]
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time


def read_schedstat_wait():
    """Read cumulative runqueue wait time (ns) from /proc/self/schedstat."""
    with open("/proc/self/schedstat") as fh:
        return int(fh.read().split()[0])


def cpu_hog_with_comm(duration_s: float) -> None:
    """CPU-bound spinner with comm 'bash' (interactive-classified)."""
    import ctypes
    ctypes.CDLL(None).prctl(15, b"bash", 0, 0, 0)
    end = time.monotonic() + duration_s
    x = 0
    while time.monotonic() < end:
        x += 1


def waker_with_comm(duration_s: float, results: dict) -> None:
    """2ms-sleep waker with comm 'bash' — measures runqueue wait per wake."""
    import ctypes
    ctypes.CDLL(None).prctl(15, b"bash", 0, 0, 0)

    stat_path = "/proc/self/schedstat"
    end = time.monotonic() + duration_s

    def read_wait():
        with open(stat_path) as fh:
            return int(fh.read().split()[0])

    prev = read_wait()
    # record (elapsed_s, wait_delta_ns) per wake
    start = time.monotonic()
    samples = []
    while time.monotonic() < end:
        time.sleep(0.002)
        cur = read_wait()
        delta = cur - prev
        prev = cur
        elapsed = time.monotonic() - start
        samples.append((round(elapsed, 1), delta))
        # include ALL deltas (zero-wait = fast-path dispatch, which IS
        # the signal that the scheduler is not adding overhead)
        results["all_waits"].append(delta)
        if elapsed <= 20:
            results["early_waits"].append(delta)
        elif elapsed >= duration_s - 20:
            results["late_waits"].append(delta)
    results["samples"] = samples


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Behavior demotion wake-latency experiment")
    parser.add_argument("--scheduler", choices=["eevdf", "foresight"], default="foresight")
    parser.add_argument("--duration", type=int, default=60, help="experiment duration (s)")
    args = parser.parse_args(argv)

    BIN = "/root/WSL2-Linux-Kernel/tools/sched_ext/build/bin"

    # start scheduler (or ensure none for EEVDF)
    if args.scheduler == "foresight":
        subprocess.run(["pkill", "-9", "-f", "foresight_sched|scx_simple"],
                       capture_output=True)
        # bpffs mount (fresh wsl session = fresh mount ns)
        subprocess.run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"],
                       capture_output=True)
        proc = subprocess.Popen([f"{BIN}/foresight_sched"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        state = open("/sys/kernel/sched_ext/state").read().strip()
        print(f"scheduler: {args.scheduler}, state: {state}")
    else:
        subprocess.run(["pkill", "-9", "-f", "foresight_sched|scx_simple"],
                       capture_output=True)
        time.sleep(2)
        print(f"scheduler: {args.scheduler} (kernel default)")
        proc = None

    # start 3 CPU hogs (interactive-classified) + 1 waker
    results = {"all_waits": [], "early_waits": [], "late_waits": [], "samples": []}
    hogs = []
    for _ in range(3):
        t = threading.Thread(target=cpu_hog_with_comm, args=(args.duration,))
        t.start()
        hogs.append(t)

    time.sleep(1)  # let hogs start before the waker

    wt = threading.Thread(target=waker_with_comm,
                          args=(args.duration - 1, results))
    wt.start()

    print(f"experiment running for {args.duration}s with 3 CPU hogs (comm=bash)...")
    wt.join()
    for t in hogs:
        t.join()

    # analysis
    all_waits = [w / 1000.0 for w in results["all_waits"]]  # ns -> μs
    early = [w / 1000.0 for w in results["early_waits"]]
    late = [w / 1000.0 for w in results["late_waits"]]

    print(f"\n=== results ({args.scheduler}) ===")
    print(f"total wake samples: {len(all_waits)}")
    print(f"waits > 0μs: {sum(1 for w in all_waits if w > 0)}")
    if all_waits:
        import statistics
        print(f"p50: {statistics.median(all_waits):.1f} μs")
        print(f"p99: {sorted(all_waits)[int(len(all_waits)*0.99)]:.1f} μs")
        print(f"max: {max(all_waits):.1f} μs")
    if early:
        print(f"early (first 20s): mean {sum(early)/len(early):.1f} μs, n={len(early)}")
    if late:
        print(f"late (last 20s):   mean {sum(late)/len(late):.1f} μs, n={len(late)}")

    # stop scheduler
    if proc:
        proc.terminate()
        proc.wait(timeout=5)

    # write results for the comparison
    outfile = f"/root/foresight-sched/bench/wake_exp_{args.scheduler}.json"
    import json
    with open(outfile, "w") as fh:
        json.dump({
            "scheduler": args.scheduler,
            "total_samples": len(all_waits),
            "nonzero_waits": sum(1 for w in all_waits if w > 0),
            "p50_us": statistics.median(all_waits) if all_waits else 0,
            "p99_us": sorted(all_waits)[int(len(all_waits)*0.99)] if all_waits else 0,
            "max_us": max(all_waits) if all_waits else 0,
            "early_mean_us": sum(early)/len(early) if early else 0,
            "late_mean_us": sum(late)/len(late) if late else 0,
            "all_waits_us": all_waits,
        }, fh, indent=2)
    print(f"results: {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
