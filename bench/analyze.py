#!/usr/bin/env python3
"""foresight-sched Phase 4: benchmark analyzer.

Reads the raw JSON from run_bench.py and produces a comparison report
with the pre-registered acceptance check.
"""
from __future__ import annotations

import json
import statistics
import sys


def main(argv=None) -> int:
    path = argv[0] if argv else "results.json"
    with open(path) as fh:
        results = json.load(fh)

    print("=" * 72)
    print("foresight-sched Phase 4 benchmark report")
    print("=" * 72)
    print(f"\nSource: {path}  ({len(results)} measurements)\n")

    by_key: dict[tuple, list[dict]] = {}
    for r in results:
        by_key.setdefault((r["config"], r["regime"]), []).append(r)

    metric_keys = ["wake_latency_p50_us", "wake_latency_p99_us",
                   "wake_latency_mean_us", "batch_iters_per_sec"]

    # per (config, regime) table
    for (config, regime), items in sorted(by_key.items()):
        print(f"  {config} / {regime}:")
        for mk in metric_keys:
            vals = [r[mk] for r in items if mk in r and isinstance(r[mk], (int, float))]
            if vals:
                mean_v = statistics.mean(vals)
                unit = " us" if "latency" in mk else ""
                print(f"    {mk:<30} {mean_v:>10.1f}{unit}")
            else:
                print(f"    {mk:<30} {'n/a':>10}")
        print()

    # pre-registered acceptance
    mixed_cfgs = {}
    for (config, regime), items in by_key.items():
        if regime == "mixed":
            mixed_cfgs[config] = items

    if "eevdf" in mixed_cfgs and "foresight" in mixed_cfgs:
        e_p99 = [r["wake_latency_p99_us"] for r in mixed_cfgs["eevdf"]
                 if "wake_latency_p99_us" in r]
        f_p99 = [r["wake_latency_p99_us"] for r in mixed_cfgs["foresight"]
                 if "wake_latency_p99_us" in r]
        e_batch = [r["batch_iters_per_sec"] for r in mixed_cfgs["eevdf"]
                   if "batch_iters_per_sec" in r]
        f_batch = [r["batch_iters_per_sec"] for r in mixed_cfgs["foresight"]
                   if "batch_iters_per_sec" in r]

        print("=" * 72)
        print("PRE-REGISTERED ACCEPTANCE (mixed regime)")
        print("=" * 72)
        if e_p99 and f_p99:
            e_mean = statistics.mean(e_p99)
            f_mean = statistics.mean(f_p99)
            delta = (e_mean - f_mean) / e_mean * 100.0 if e_mean > 0 else 0.0
            print(f"  p99 wake latency: EEVDF {e_mean:.1f} us, foresight {f_mean:.1f} us")
            print(f"  delta: {delta:+.1f}%  (gate: >= +15%)")
            print(f"  latency verdict: {'PASS' if delta >= 15.0 else 'FAIL'}")
        if e_batch and f_batch:
            e_m = statistics.mean(e_batch)
            f_m = statistics.mean(f_batch)
            b_delta = (f_m - e_m) / e_m * 100.0 if e_m > 0 else 0.0
            print(f"  batch throughput: EEVDF {e_m:.0f}, foresight {f_m:.0f}")
            print(f"  delta: {b_delta:+.1f}%  (gate: >= -10%)")
            print(f"  batch verdict: {'PASS' if b_delta >= -10.0 else 'FAIL'}")

    print("\nNote: measurements are from a 4-vCPU WSL2 VM; absolute values")
    print("differ from bare metal. The comparison BETWEEN schedulers under")
    print("identical load is the valid signal.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
