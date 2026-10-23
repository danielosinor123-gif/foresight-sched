# foresight-sched — Phase 0 & 1 Report

### The prediction, running in kernel space

*Result of the build session of Oct 20–22, 2026. Everything below was
executed and verified live on the target machine.*

---

## Executive summary

The System Software Futures study predicted AI-Aware OS Scheduling
(impact 36.6, mainstream ~2028.7). This project made it real:

1. **A custom Linux kernel was compiled** (Microsoft's WSL2 source,
   6.18.33.2, with `CONFIG_SCHED_CLASS_EXT=y` — the one flag Microsoft
   ships disabled) and the machine now boots it.
2. **A workload-class-aware sched_ext scheduler was built, loaded into
   that kernel, and proven**: strict-priority lanes (interactive before
   batch), classification-driven routing, verifier-gated loads, clean
   fallback to the default scheduler on every unload.
3. **A live classification daemon closed the userland↔kernel loop**:
   it watches /proc, translates pid namespaces through a kernel-provided
   probe map, and rewrites classifications at runtime — both scheduler
   lanes proven climbing from live daemon classification.
4. **The whole thing was built by a multi-agent protocol**: writers
   produced components, adversarial reviewers attacked them, the
   maintainer merged only what survived, and deterministic tests were
   the final arbiter.

## Environment

| Piece | State |
|---|---|
| WSL2 kernel 6.18.33.2-microsoft-standard-WSL2**+** | custom-built, boots daily (`+` = locally modified) |
| In-tree sched_ext examples (scx_simple etc.) | built; scx_simple load/run/unload proven first |
| foresight_sched (BPF policy + C loader) | built `-Wall -Werror` clean against the tree |
| foresight_daemon.py (live classifier) | 1,196 lines, stdlib-only, fixed per review |
| 24h soak | running since Oct 22 (self-terminating via `timeout 86400`) |

## Phase 0 receipts

- Load → `state: enabled`; SIGINT → `disabled`, "EXIT: unregistered
  from user space", zero verifier refusals.
- **The headline number: `enq interactive=5026` vs `normal=25`** —
  CPU-saturating spinners seeded via CLI took the priority lane at
  full re-enqueue rate; the strict-priority thesis executed in kernel
  space.
- Hostile inputs (pid 0, garbage, overflow) all rejected loudly (exit 1).

## Phase 1 receipts

- Loader pins `task_class` + `pid_probe` to `/sys/fs/bpf/foresight/`
  for the daemon; pins exist exactly while the scheduler runs and every
  error path unwinds them.
- A `sched_process_exec` tracepoint records **comm → kernel-global pid**
  at every exec — the kernel itself provides the pid-namespace oracle.
- The daemon discovers the live namespace offset (dual-probe, agreement
  required), scans /proc every 2s, mirrors the loader's class rules,
  and updates classifications through bpftool.
- Acceptance run: `enq normal=474 interactive=26 batch=33` with the
  daemon classifying bash×2, chrome → interactive, cargo → batch —
  **both lanes climbing from live classification**.

## The multi-agent protocol ledger

| Agent | Deliverable | Verdict | Headline catch |
|---|---|---|---|
| Writer A | kernel-side BPF scheduler | SHIP (Reviewer 1) | found the 6.18 API renames (`scx_bpf_dsq_insert`/`dsq_move_to_local`) |
| Writer B | C loader/control plane | FIX-THEN-SHIP (Reviewer 2) | live-validated the loader with a stub; discovered the WSL2 pid-namespace offset |
| Reviewer 1 | adversarial: BPF correctness | SHIP w/ 2 prose fixes | proved `SCX_OPS_OPEN` populates SCX_SLICE_DFL (alleged critical: refuted) |
| Reviewer 2 | adversarial: hostile inputs | FIX-THEN-SHIP | 3 silent-wrong bugs: cross-class pid "last wins" false; max_entries not contract-checked; namespace caveat understated |
| Writer C | live classification daemon | FIX-THEN-SHIP (Reviewer 3) | discovered the offset DRIFTS mid-session; built re-measurement |
| Reviewer 3 | adversarial: daemon | FIX-THEN-SHIP | **BLOCKING: the drift "repair" was self-corruption** — pid cohorts are birth-bound; re-keying wrote provably-wrong pids (live-proven, +173→+187) |
| Fix agent | applied Reviewer 3's findings | validated 6/6 | sticky per-task offsets: one bash entry kept its recorded gpid through 5 natural drifts while new cohorts keyed correctly |

The protocol's earned-keep moment: Writer C's proudest feature (drift
repair) was its most dangerous bug, and only the adversarial reviewer —
proving the math from live captures — caught it. Reviews are cheap
opinions; tests are expensive facts; both gates fired.

## Engineering lessons (all now encoded in code comments)

1. **`SCX_OPS_ATTACH` auto-attaches every program** — manually
   attaching the tracepoint too produced `-EEXIST` → `SCX_BUG` exit →
   orphaned pins. Fix: trust the auto-attach, verify the link after.
2. **Pid-namespace offsets are per-birth-cohort, not global** — a
   task's kernel-global pid is fixed at birth; only tasks born after
   a drift carry the new offset. Sticky per-task keys are the only
   correct model.
3. **WSL2 has no auto-mounted bpffs and private mount namespaces per
   wsl.exe invocation** — the daemon must share the scheduler's mount
   namespace (`nsenter -t <pid> -m`).
4. **PowerShell quoting is hostile to inline bash** — every non-trivial
   WSL command went through script files copied in and LF-normalized.

## Soak status — FINAL (Oct 23, 2026): PASSED

| Receipt | Value |
|---|---|
| Duration | 28.0 hours continuous (100,947 s — ran past the 24h gate) |
| Scheduling decisions | 573,624 |
| Restarts during run | 0 (single uninterrupted scheduler load) |
| Panics / anomalies / verifier refusals | 0 / 0 / 0 |
| Clean unload after the run | "EXIT: unregistered from user space", state → disabled, 0 pins |

Engineering finding #5: the `timeout 86400` wrapper never fired —
host sleep cycles defeated the guest-side timer (WSL2 clock skew vs
`setitimer` deadlines; the log ticked smoothly across the 86,400s
mark). Long guest-side soaks need an in-guest wall-clock watchdog,
not a host-side timeout wrapper. Stopped manually at 28h; the manual
SIGINT doubled as the clean-unload-after-long-run test — passed.

## Honest remaining gaps

- Phase 1 "done-when" (measurably better interactive latency vs the
  default scheduler) needs the Phase 4 benchmark battery — the
  mechanism is proven, the performance claim is not yet measured.
- The daemon's residual exposure: a task born just before a drift and
  first classified after it gets the new offset (one-scan-window,
  documented); pid reuse within a scan window (documented).
- The classification rules table is static and mirrored in two files
  (loader C + daemon Python) — Phase 1.5 should generate one from the
  other.

## Files

- `src/foresight_sched.bpf.c` — kernel-side policy + pid probe
- `src/foresight_sched.c` — loader/control plane (pins, contract checks)
- `src/foresight_daemon.py` — live classifier
- `reference/tools_sched_ext/` — the kernel tree's examples (ground truth)
- Kernel: `C:\wslk\bzImage-schedext` (rollback: remove `kernel=` line in `.wslconfig`)
