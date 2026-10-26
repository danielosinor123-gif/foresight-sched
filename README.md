# foresight-sched

### A kernel-resident, AI-aware CPU scheduler — the 2029 prediction, loaded into a real Linux kernel

The System Software Futures study predicted **AI-Aware OS Scheduling**
(impact 36.6, mainstream ~2028.7): kernel schedulers that understand
workload semantics and place tasks across cores accordingly.
This project builds that prediction for real — not a simulation — using
**sched_ext**, the Linux kernel's sanctioned interface for custom
schedulers (mainline since kernel 6.12, BPF-verified, used in production
at Meta).

Built with the **2-writer / 2-reviewer multi-agent protocol** (see
"Build protocol") on top of the [Foresight](https://github.com/danielosinor123-gif/foresight) userland layer,
which supplies telemetry and workload classification.

---

## First, the hardware question (read this before anything)

**This is not server-grade-only technology.** The Linux kernel — and
sched_ext with it — is architecture-portable. It runs the same code on
everything from a smartwatch to a supercomputer:

| Environment | Can run foresight-sched? | Notes |
|---|---|---|
| QEMU / VirtualBox / WSL2 VM | ✅ primary dev target | kernel crash = restore snapshot; zero risk |
| Any x86-64 laptop with Linux 6.12+ | ✅ | your own machine, dual-boot or live USB |
| Raspberry Pi 5 (ARM64) | ✅ | real bare-metal hardware, unbrickable via SD reflash |
| 128-core Xeon server | ✅ | where the *extreme tuning* lives — not a requirement |

The "Meta runs this on Xeon fleets" fact is about *scale*, not
*permission*: the identical interface is open to a VM on a laptop. The
gates to the "full thing" are kernel version (6.12+) and review culture —
never proprietary hardware.

## What "real" means here (no asterisks hidden)

- The scheduler executes **in kernel space**, scheduling real processes
  with real kernel privilege
- The **real eBPF verifier** checks every instruction before load — a
  faulty scheduler *cannot* take the kernel down by design; worst case
  the kernel falls back to its default scheduler
- sched_ext is **mainline upstream Linux** — the same mechanism, not a
  fork, not a patch-set of our own kernel
- Precedent: `scx_rusty` — a sched_ext scheduler **written in Rust** —
  ships in the kernel's official scheduler toolbox; our language rule
  (Rust over C++) follows the ecosystem's own direction

## The long run — what we hope to achieve

> **Status (Oct 26, 2026): Phase 0 ✅ COMPLETE · Phase 1 ✅ COMPLETE ·
> Phase 2 ✅ COMPLETE · Phase 3 ✅ COMPLETE ·
> Phase 4 🔄 benchmark battery RAN — batch throughput ✅ PASS (+3%),
> wake latency ❌ FAIL (p99 2.1ms vs 55μs, n=1 samples — needs
> methodology refinement) · full honest results in
> [bench/results.json](bench/results.json) and
> [BENCHMARK-PLAN.md](BENCHMARK-PLAN.md)**

**Phase 0 — Prove the loop (now ✅, Oct 21 2026; soak gate closed Oct 23).**
A minimal sched_ext scheduler loads in a VM, survives the verifier, runs
the system, and unloads cleanly back to the default scheduler.
*Done when: boot → load → run 24h → unload, zero kernel panics.*
**✅ RECEIPTS: 28.0h continuous soak, 573,624 scheduling decisions,
zero anomalies, zero panics, single uninterrupted load (no restarts),
clean unload after the run ("EXIT: unregistered from user space").**

**Phase 1 — Workload-class awareness.**
Scheduler policy that treats interactive, batch and ML-class tasks
differently (interactive gets latency priority; batch gets throughput
lanes) — fed by Foresight's classifier over a shared map.
*Done when: mixed workload shows measurably better interactive latency
than the default scheduler, with batch throughput within 10%.*

**Phase 2 — Telemetry-driven self-tuning (✅ core shipped, Oct 25 2026).**
EWMA baselines and anomaly signals (the Foresight anomaly engine)
dynamically reweight policy knobs: the scheduler adapts to *this*
machine's workload rhythm instead of static profiles.
*Done when: policy weights visibly adapt within a session and the
adaptation is logged and explainable.*
**✅ RECEIPTS: kernel behavior demotion fired live (5 explainable,
kernel-authoritative events); adaptive knob fired live —
`interactive_slice_ns 20ms -> 10ms (EWMA 72.3/s; hot rule: >50/s for 3
consecutive cycles)`, visible in the live knobs map; sticky-offset drift
repair live; rate math matches scheduler counters exactly. See
[PHASE-2-REPORT.md](PHASE-2-REPORT.md) — including the lane-contention
semantic finding that calibrates Phase 4.**

**Phase 3 — Energy-aware variant.**
On battery, bias the same policy toward efficiency (batch deferral,
aggressive idle) — the Energy-Adaptive Scheduling prediction (mainstream
2023.5) applied at kernel level.
*Done when: measurable battery-life delta on a controlled workload.*

**Phase 4 — Benchmark honestly.**
Tail latency (p99), throughput, fairness, and energy against
`scx_simple`, `scx_rusty`, and the kernel default (EEVDF). No cherry-
picking: publish losses too.
*Done when: a reproducible benchmark suite + public report.*

**Phase 5 — The real last mile: upstream.**
Follow kernel review culture — small patches, adversarial review,
maintainer sign-off — toward contributing to the `scx` community.
*Done when: a patch or policy idea survives upstream review.*

**North star.** The prediction says AI-aware scheduling goes mainstream
in ~2028-29. The long-run hope is to be *early with receipts*: a working,
benchmarked, review-hardened scheduler that demonstrates the prediction
was buildable today — and to close the loop that started with the
prediction study: **study → plan → userland prototype (Foresight) →
kernel-resident implementation (this) → upstream contribution.**

## Architecture

```
┌─────────────────────────── userspace (Rust) ──────────────────────────┐
│ foresight control plane: telemetry, workload classification,        │
│ EWMA baselines/anomalies, policy knobs, benchmarks, logging          │
└───────────────┬──────────────────────────────────────────────────────┘
                │ BPF maps (shared state) + scheduler struct
┌───────────────▼──────────────────── kernel (BPF) ─────────────────────┐
│ foresight-sched BPF scheduler: pick_next_task / enqueue / dispatch    │
│ policy driven by class hints + knobs from the control plane           │
│ gatekept by the eBPF VERIFIER before load; instant fallback to       │
│ the kernel default scheduler on unload                               │
└───────────────────────────────────────────────────────────────────────┘
```

**What "AI-aware" honestly means in-kernel:** BPF programs cannot host
neural networks — and we won't pretend otherwise. The intelligence lives
in the Rust control plane (classification, baselines, adaptation); the
kernel component executes a fast, verified policy that *consumes* those
signals. This is exactly how production systems split the problem — and
it keeps every byte of kernel code verifiable.

## Build protocol (the experiment this project runs on)

Every layer is built by a multi-agent protocol that mirrors kernel
review culture:

| Agent | Mandate |
|---|---|
| Writer A + Writer B | build two components of the same layer, in parallel |
| Reviewer 1 | adversarial *correctness* lens: races, error paths, verifier rejections |
| Reviewer 2 | adversarial *hostile-world* lens: malformed inputs, resource leaks, unload edge cases |
| Maintainer (orchestrator) | merges, rejects weak reviews, runs deterministic tests — **tests are the final arbiter, not opinions** |

Rule carried over from the study: reviews are cheap opinions; tests are
expensive facts. No code is trusted until it executes.

## Safety model

1. **Verifier-gated by design** — the eBPF verifier must approve every
   scheduler before it can touch the kernel.
2. **Disposable blast radius** — development happens in a VM (QEMU/WSL2);
   a kernel panic costs a snapshot restore, never your data.
3. **Instant retreat** — sched_ext unloads at any time and the kernel
   reverts to its default scheduler; there is no permanent state.
4. **No custom kernel** — we never patch or fork the kernel; we use the
   sanctioned interface. Uninstall = unload.

## Honest limitations

- Requires **Linux 6.12+** (WSL2's kernel version must be checked; QEMU
  with a modern distro always works).
- Perf characteristics tuned in a VM don't perfectly transfer to big
  multi-core servers — Phase 5 territory, stated openly.
- In-BPF "AI" is policy logic, not learning — by design (verifiability).
- Upstream merge is governed by the kernel community's review ladder —
  slow by intent; that's the point of it.
- Benchmark comparisons depend on workload realism; we publish losses.

## References

- sched_ext — extensible BPF scheduler class, mainline since Linux 6.12
- `scx` community toolbox — `scx_rusty` (Rust), `scx_lavd`, `scx_bpfland`
- Meta production reports of sched_ext scheduler deployments
- System Software Futures study (this project's source prediction)

---

## Where to find this project

- **GitHub:** https://github.com/danielosinor123-gif/foresight-sched
- **The arc:** [System Software Futures](https://github.com/danielosinor123-gif/system-software-futures) (the prediction) → [Foresight](https://github.com/danielosinor123-gif/foresight) (userland prototype) → **foresight-sched** (kernel-resident implementation)
- **Earlier studies:** [The NEXT Top Industries for DS/ML](https://github.com/danielosinor123-gif/ds-ml-industry-prospects) · [ML Niche Challengers](https://github.com/danielosinor123-gif/ds-ml-niche-challengers)
- Foresight — the userland layer feeding this scheduler

---

*Phase 0 begins with: check the environment (WSL2 kernel version), then
run the 2-writer / 2-reviewer experiment on the first component.*
