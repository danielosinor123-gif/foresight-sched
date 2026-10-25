#!/usr/bin/env python3
"""
foresight_daemon.py - Phase 1 live classification + Phase 2
telemetry-driven self-tuning daemon for the foresight_sched
sched_ext scheduler (stdlib-only Python 3).

WHAT IT DOES
============
Closes the userland->kernel loop that Phase 0 opened: the sched_ext
scheduler (kernel side, foresight_sched.bpf.c) classifies every task by
looking the task's pid up in the `task_class` BPF hash (u32 pid -> u8
class: 0=normal, 1=interactive, 2=batch) and routes class 1 into a
priority DSQ. Phase 0 seeds that map only from CLI pids. This daemon
watches /proc, matches process comm names against the same rules table
the C loader documents, and live-updates task_class through bpftool:

    watch /proc/[0-9]*/comm every 2s
        -> comm in rules table? compute kernel-global pid (see below)
        -> bpftool map update pinned .../task_class key hex <LE u32> value hex <class>
        -> scheduler routes that task into the interactive/batch lane

THE PID-NAMESPACE STORY (why the probe exists)
=============================================
The BPF side matches KERNEL-GLOBAL pids (task_struct->pid, i.e. pids as
seen from the init pid namespace). The daemon runs inside the WSL2
distro's pid namespace, where /proc shows namespaced pids. The mapping
the two pid pools (one per namespace level) only advance in lockstep
while every new task is born inside our namespace, so their difference
is an additive offset - but that offset is NOT knowable from inside:
WSL2's /proc/<pid>/status NSpid line hides the global pid (it lists
only the namespace-local number), and WORSE: WSL2's root-namespace
infrastructure (session/relay helpers spawned for every wsl.exe
command) consumes kernel-global pids WITHOUT consuming namespaced
ones, so the offset DRIFTS upward during a session (observed live:
+170 early in a session, +183 an hour later - same scheduler, same
namespace; any hardcoded value would misclassify innocent tasks). The
kernel side helps: a tracepoint on
sched_process_exec writes comm -> kernel-global pid into the `pid_probe`
map on every exec. So the daemon execs a uniquely named copy of
/bin/sleep (comm = executable basename, truncated to 15 chars), finds
that comm in pid_probe, and subtracts its OWN namespaced pid
(subprocess.Popen.pid) to get the live offset.

PIN LIFECYCLE CONTRACT (with foresight_sched.c, the loader)
===========================================================
The loader pins task_class and pid_probe under /sys/fs/bpf/foresight
ONLY while it runs; clean teardown and every error path unpin them.
Consequences the daemon honors:
  - preflight: both pins must exist, else exit non-zero with
    "is the scheduler running?" (never start without the scheduler);
  - every loop pass re-checks the pins: if they vanish (scheduler
    stopped or crashed) the daemon prints one line and exits 0 -
    the scheduler's map is gone, there is nothing left to update;
  - the daemon also notices the rarer race where the scheduler is
    restarted so fast that the pins re-appear before one poll: it
    compares bpftool map ids every pass and resets its bookkeeping
    when a map was replaced by a fresh instance.

OFFSET-DISCOVERY DESIGN AND FAILURE MODES
=========================================
Per attempt, TWO probes with different random names run concurrently;
both must yield the SAME offset (within one attempt they always do
under correct operation - the offset is constant at any instant and
only drifts across minutes, so disagreement means something is deeply
wrong and the attempt is retried). Failure modes
handled: probe not appearing in pid_probe within the poll window
(retried a couple of times with fresh names, then a loud fatal);
bpftool dump/timeout/parse errors (retried, never crash); an insane
offset outside 0 <= offset < /proc/sys/kernel/pid_max (reviewer NOTE:
the bound is derived live instead of a hardcoded 10000, which long
sessions can legitimately exceed; fatal: a matched entry cannot be
ours - names are unique per run); scheduler death mid-discovery (pins
check -> clean exit per the contract above). Probes are always
terminated, their /tmp files removed, and their pid_probe entries
deleted (best-effort) in a finally block - no orphaned executables.
Stale /tmp/fsxprobe_* files from a SIGKILLed previous run are swept
at startup.

Because the offset DRIFTS during a session (see the pid-namespace
story), the classification loop re-measures it with a single fresh
probe pair every OFFSET_RECHECK_PASSES passes (~30s at the 2s
cadence). What drift MEANS - and why nothing is "repaired" on drift
(reviewer BLOCKING fix: the old delete-and-re-key repair was
self-corruption):

  - A task's kernel-global pid is assigned at BIRTH and never
    changes. The offset is a birth-cohort property: every birth
    inside our namespace consumes one pid from BOTH pools in
    lockstep; only root-namespace births (WSL2 infrastructure)
    consume a kernel-global pid without a namespaced one, so
    cohort offsets are monotone NON-DECREASING over a session.
  - A task classified with the offset live at (or near) its birth
    therefore has a CORRECT task_class key for its whole life,
    however far the offset drifts afterwards. Each tracked task
    records the exact global pid written at classification time
    (state: ns_pid -> (recorded global pid, class)) and is reaped
    by that recorded pid.
  - Drift consequently affects ONLY tasks first classified after
    it: those are keyed with the current offset. The old behavior -
    delete every tracked entry and re-key it with the new offset -
    was self-corruption: ns_pid + new_offset OVERSHOOTS the true
    global pid of every task born before the drift (cohort offsets
    only grow), so the "repair" deleted correct-at-write keys and
    rewrote provably-wrong ones (observed live: one bash entry
    re-keyed 4+ times as the offset drifted +173 -> +187, every
    rewrite wrong).
  - Reaps, the shutdown cleanup and the map-id reset only ever
    touch entries the daemon itself wrote this run, so the
    maintainer's Phase 0 --interactive/--batch seeds are never
    clobbered. A clean SIGINT/SIGTERM exit deletes everything this
    generation wrote (reviewer SHOULD-FIX); entries orphaned by a
    SIGKILL or a fatal persist until the scheduler unloads.

Known limitations (accepted for Phase 1): a namespaced pid reused
within one 2s scan window by a task with an IDENTICAL comm is
indistinguishable from its predecessor - it silently inherits the
predecessor's recorded entry, and the dead task's global pid lingers
in the map until the kernel recycles it. A task born just BEFORE a
drift but first classified after it is keyed with the new offset
(exposure bounded by one recheck interval - identical in the old
design, which additionally corrupted every already-tracked task).

PHASE 2 (telemetry-driven self-tuning) - additive, same loop
============================================================
Two new controllers share the existing 2s loop, its signal
discipline and its exception ladder (NO new exit codes:
SchedulerGone -> clean exit 0, bpftool failures -> fail_streak ->
exit 10, exactly like classification):

1. Adaptive-knob controller (run_knob_cycle). Reads the pinned
   `stats` ARRAY (a Phase 0 map, NEWLY PINNED in Phase 2: key u32
   0..2 -> u64 per-class enqueue counters, 0=normal 1=interactive
   2=batch) every cycle and derives per-lane enqueue RATES from
   counter deltas over the MEASURED wall time between reads - never
   the nominal 2s, because an offset-recheck pass runs a probe pair
   with a 6s poll window and a large demotion backlog also stretches
   a pass; dividing those deltas by 2.0 would overstate the rate up
   to ~4x and could fire the hot rule on a quiet system. An EWMA
   (alpha 0.3) of the interactive rate drives a single-knob
   hysteresis on the ONE field v1 owns, knobs[0].interactive_slice_ns:
     - the first 10 rate observations are warmup, observation-only;
     - EWMA > 50/s on 3 consecutive evaluated cycles -> 10ms;
     - EWMA < 25/s on 5 consecutive evaluated cycles -> back to 20ms;
     - every actual change prints ONE explainable line: old value,
       new value, the EWMA number, the rule, the consecutive-cycle
       count. There are NO other knob writes in the daemon.
   The write is a full-struct read-modify-write: the current knobs[0]
   is dumped and re-uploaded with batch_slice_ns, demote_streak and
   _pad copied through untouched (knobs_rebuild). The daemon ADOPTS
   the live value read-only at startup - a previous daemon generation
   may have left 10ms in place, and assuming the loader's seed would
   print a bogus 'old value' on the first firing. A knobs[0] value
   that is not exactly the contract's 24 bytes latches knob writes
   off for the rest of the run instead of corrupting a struct whose
   layout the daemon does not recognize.

2. Behavior-demotion listener (drain_demotions). The kernel
   behavior-demotes a task (interactive -> batch after demote_streak
   consecutive full slices) and records the event in the pinned
   `demotions` HASH: key u32 KERNEL-GLOBAL pid -> { u64 ts_ns;
   u8 from_class; u8 to_class; u16 streak; }. Each cycle the daemon
   dumps the map, prints ONE explainable line per event, adopts the
   pid into `kernel_managed`, and DELETES the entry (the event
   lifecycle is the daemon's job in userspace; the kernel never
   reclaims entries).
   THE CROSS-COMPONENT SUBTLETY - this is the one that matters: the
   classifier SKIPS every pid in kernel_managed. Without the skip,
   the daemon's comm-based re-classification would overwrite the
   kernel's demotion every 2s cycle and the kernel would re-demote
   forever: classify interactive -> kernel demotes -> daemon
   re-classifies interactive -> ... With it, classification
   authority for that pid passes to the kernel for the pid's
   remaining life (only reaps still run: a kernel-managed pid that
   dies or stops comm-matching must not leave a stale task_class
   entry - pid-reuse hygiene outranks the handoff). Entries are
   KERNEL-GLOBAL pids (the demotions key space, same as task_class),
   so reconcile compares them against the exact global pid it would
   itself write (recorded global pid for tracked tasks; ns_pid + live
   offset for first sightings). Entries leave the set when the pid
   disappears from /proc - retired each pass against the global pids
   of every live task, which is exact for daemon-tracked tasks and
   cohort-approximate for untracked ones (the same one-window
   aliasing residual the Phase 1 limitations already document).
   kernel_managed is per-daemon-generation: after a daemon restart a
   still-demoted task costs at most one extra demotion round before a
   fresh event re-registers it.

Preflight now demands all FIVE pins (task_class, pid_probe, stats,
knobs, demotions) with the same "is the scheduler running?"
discipline (exit 2): a Phase 1-only scheduler is refused outright,
never quietly half-driven. The in-loop pins_exist() check
deliberately still keys off the two Phase 1 pins - the loader pins
and unpins the whole set as one unit, so they vanish exactly when
the scheduler does. A detected scheduler restart (map-id change)
resets ALL Phase 2 bookkeeping: fresh counters (the EWMA baseline
described a dead instance), a fresh loader-seeded knobs value
(re-adopted read-only next cycle), and an empty demotions map
(kernel_managed dies with the old instance; live demoted tasks
re-register through fresh events).

HOW TO RUN (WSL2 gotchas found the hard way, empirically)
=========================================================
Run INSIDE the WSL2 distro as root, where the scheduler was started:
  1. bpffs must be mounted: `mount -t bpf bpf /sys/fs/bpf` (WSL2
     distros do NOT mount it at boot; without it the loader itself
     fails to pin).
  2. WSL2 + systemd gives EVERY wsl.exe session its own private mount
     namespace. The pins are only visible where the scheduler's mount
     namespace is. From another session use:
         nsenter -t $(pgrep -x foresight_sched) -m -- python3 foresight_daemon.py
     or run scheduler and daemon from the same shell.
  3. The scheduler binary:
     /root/WSL2-Linux-Kernel/tools/sched_ext/build/bin/foresight_sched
     (check /sys/kernel/sched_ext/state == "enabled").

EMPIRICALLY VERIFIED bpftool FORMATS (bpftool v7.7.0 on this kernel)
====================================================================
- JSON dump: [{"key": ["0x64","0x70",...], "value": ["0x2e","0x04",
  "0x00","0x00"], "formatted": {...}}, ...] - key/value are ARRAYS of
  "0xNN" strings (little-endian memory image). The "formatted" field
  is BTF pretty-printing and is deliberately ignored (absent without
  BTF). The parser also tolerates a single hex-string form.
- key/value hex on the command line: ONE ARGV TOKEN PER BYTE
  ("key hex 9c 01 00 00"). A single quoted token "9c 01 00 00" FAILS
  with "error parsing byte" - verified live.
- exit code on error is 254 with "Error: ..." on stderr; the daemon
  captures stderr and never lets bpftool output crash it.

--TEST MODE
===========
Spawns two fake workloads (Python children that prctl(PR_SET_NAME)
themselves to comm "chrome" and "cargo" and busy-loop ~20s) so the
maintainer can watch the scheduler's per-class enqueue counters climb
in BOTH lanes. These two comms are TEST-ONLY rules (see TEST_RULES) -
they are NOT in the mirrored C table, which mirrors class_rules from
foresight_sched.c EXACTLY.

EXIT CODES: 0 clean (signal, or pins vanished) | 2 pins missing at
preflight | 3 bpftool not found | 4 offset discovery (or repeated
offset rechecks) failed | 5 not
root | 6 usage | 10 classification loop broken (10 consecutive
failed passes, or a startup bpftool / test-spawn failure).
SIGINT/SIGTERM -> kill test children, delete our map entries,
exit 0.
"""

import glob
import json
import os
import random
import shutil
import signal
import struct
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Contract constants (must match foresight_sched.c / foresight_sched.bpf.c)
# ---------------------------------------------------------------------------

PIN_DIR = "/sys/fs/bpf/foresight"
PIN_TASK_CLASS = PIN_DIR + "/task_class"  # BPF hash: u32 global pid -> u8 class
PIN_PID_PROBE = PIN_DIR + "/pid_probe"    # BPF hash: char[16] comm -> u32 global pid
# Phase 2 pins (contract with the BPF side + loader; all five pins live
# and die with the scheduler exactly like the two above):
#   stats:     ARRAY, key u32 0..2 -> u64 per-class enqueue counters
#              (0=normal, 1=interactive, 2=batch). The MAP exists since
#              Phase 0; the PIN is new in Phase 2.
#   knobs:     ARRAY, key u32 0 -> struct { u64 interactive_slice_ns;
#              u64 batch_slice_ns; u32 demote_streak; u32 _pad; },
#              loader-seeded to {20000000, 20000000, 10, 0}. The daemon
#              rewrites ONLY interactive_slice_ns (read-modify-write).
#   demotions: HASH, key u32 KERNEL-GLOBAL pid -> struct { u64 ts_ns;
#              u8 from_class; u8 to_class; u16 streak; }, written by
#              the KERNEL on behavior demotion; read + DELETED here.
PIN_STATS = PIN_DIR + "/stats"          # Phase 2: enqueue counters
PIN_KNOBS = PIN_DIR + "/knobs"          # Phase 2: tunable knobs
PIN_DEMOTIONS = PIN_DIR + "/demotions"  # Phase 2: kernel demotion events

# Workload classes: the wire format of the task_class map value (u8) and
# the stats map keys. MUST match enum foresight_class in foresight_sched.c
# and the TASK_CLASS_* enum in foresight_sched.bpf.c.
CLASS_NORMAL = 0
CLASS_INTERACTIVE = 1
CLASS_BATCH = 2
CLASS_NAMES = {CLASS_NORMAL: "normal",
               CLASS_INTERACTIVE: "interactive",
               CLASS_BATCH: "batch"}

# Probe design constants. TASK_COMM_LEN is 16 *including* the NUL, so a
# comm is at most 15 chars. "fsxprobe_" (9 chars) + a 6-char random
# suffix is EXACTLY 15 - the name can never be silently truncated by
# the kernel, which would break the pid_probe lookup.
TASK_COMM_LEN = 16
PROBE_PREFIX = "fsxprobe_"
PROBE_SUFFIX_LEN = 6
PROBE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
PROBE_SRC = "/bin/sleep"
PROBE_LIFETIME_S = 30        # probe outlives the poll window by a wide margin
PROBE_POLL_WINDOW_S = 6.0    # "within a few seconds" per attempt
PROBE_POLL_INTERVAL_S = 0.5
PROBE_ATTEMPTS = 3           # initial attempt + a couple of retries
PROBE_PROBES_PER_ATTEMPT = 2 # two probes must agree (see header docstring)
# Sanity bound for a measured offset is 0 <= offset < pid_max, read
# LIVE from /proc/sys/kernel/pid_max (see offset_sanity_max()).
# Reviewer NOTE: this used to be a hardcoded OFFSET_MAX=10000, which a
# long session can legitimately exceed. PID_MAX_FALLBACK is the 64-bit
# kernel's default pid_max, used only if the sysctl is unreadable.
PID_MAX_FALLBACK = 4194304

# Classification loop tuning.
LOOP_INTERVAL_S = 2.0
UPDATE_GIVEUP_AFTER = 5        # per-pid consecutive update failures tolerated
LOOP_FAIL_GIVEUP = 10          # consecutive wholly-failed loop passes
# The pid-namespace offset DRIFTS during a WSL2 session (see header):
# re-measure it with a fresh probe pair every N loop passes (~30s). On
# drift, tracked entries KEEP the global pid recorded when they were
# classified - correct for their birth cohort - and the new offset
# applies only to tasks first seen afterwards (reviewer BLOCKING fix:
# the old delete-and-re-key "repair" corrupted correct entries).
OFFSET_RECHECK_PASSES = 15
MAP_ID_CHECK_PASSES = 5   # map-id liveness sweep every N passes (maintainer
                          # fix: 5 bpftool shows per pass was 50-90% of the
                          # pass cost under load; see call site in main())
RECHECK_GIVEUP = 5             # consecutive failed rechecks before dying

# Phase 2 controller tuning (adaptive knob + demotion listener).
# The loader seeds knobs[0] = {20000000, 20000000, 10, 0}. Phase 2 v1
# owns exactly ONE field, interactive_slice_ns, with this hysteresis:
#   interactive enqueue-rate EWMA > 50/s on 3 consecutive evaluated
#     cycles -> interactive_slice_ns = 10ms;
#   EWMA < 25/s on 5 consecutive evaluated cycles -> back to 20ms.
# Comparisons are STRICT per the contract: exactly 50.0/s or 25.0/s
# falls in the deadband and breaks both consecutive runs.
INTERACTIVE_SLICE_DEFAULT = 20000000
INTERACTIVE_SLICE_FAST = 10000000
KNOB_EWMA_ALPHA = 0.3
KNOB_WARMUP_SAMPLES = 10     # first 10 rate observations: warmup only
KNOB_HOT_RATE = 50.0
KNOB_HOT_STREAK = 3
KNOB_COOL_RATE = 25.0
KNOB_COOL_STREAK = 5
KNOB_STATUS_EVERY = 15       # one visibility line per ~30s of cycles

# knobs value struct (Phase 2 contract, x86-64 raw memory image):
#   struct { u64 interactive_slice_ns; u64 batch_slice_ns;
#            u32 demote_streak; u32 _pad; }  -> sizeof 24, natural
# alignment, no holes. "<QQII" reproduces it byte for byte; the RMW
# write refuses any blob that is not exactly this size.
KNOBS_VALUE_FMT = "<QQII"
KNOBS_VALUE_SIZE = struct.calcsize(KNOBS_VALUE_FMT)

# demotions value struct (Phase 2 contract): u64 ts_ns; u8 from_class;
# u8 to_class; u16 streak; + 4 bytes tail padding (8-aligned C struct,
# sizeof 16). unpack_from reads the 12-byte body; a shorter blob is a
# contract violation and is never adopted.
DEMOTION_VALUE_FMT = "<QBBH"
DEMOTION_VALUE_MIN = struct.calcsize(DEMOTION_VALUE_FMT)

# --test mode tuning.
TEST_CHILD_SECONDS = 20

# Every subprocess call is timeout-bounded; these cover bpftool runs.
BPFTOOL_DUMP_TIMEOUT = 15
BPFTOOL_UPDATE_TIMEOUT = 10
BPFTOOL_SHOW_TIMEOUT = 10

# Where to find bpftool, in order. The first path is where the sched_ext
# build actually puts it on this machine (verified live); the second is
# the kernel-tree in-place build location; the third is PATH.
BPFTOOL_CANDIDATES = [
    "/root/WSL2-Linux-Kernel/tools/sched_ext/build/sbin/bpftool",
    "/root/WSL2-Linux-Kernel/tools/bpf/bpftool/bpftool",
]

# ---------------------------------------------------------------------------
# Classification rules.
# ---------------------------------------------------------------------------

# keep in sync with class_rules in foresight_sched.c
#
# EXACT mirror of the static rules table in the Phase 0 loader
# (foresight_sched.c). Phase 0 prints this table under -v but never
# seeds from it; Phase 1 (this daemon) is the consumer. If a comm is
# added/renamed there, change it here the same day - these names are
# matched verbatim against /proc/<pid>/comm (at most 15 chars).
CLASS_RULES = {
    # Latency-sensitive: shells, editors, remote sessions
    "bash":  CLASS_INTERACTIVE,
    "zsh":   CLASS_INTERACTIVE,
    "ssh":   CLASS_INTERACTIVE,
    "vim":   CLASS_INTERACTIVE,
    "emacs": CLASS_INTERACTIVE,
    # Throughput-oriented: build machinery and compilers
    "make":  CLASS_BATCH,
    "ninja": CLASS_BATCH,
    "gcc":   CLASS_BATCH,
    "cc1":   CLASS_BATCH,   # gcc's per-TU worker
    "ld":    CLASS_BATCH,
    "rustc": CLASS_BATCH,
}

# TEST-ONLY rules for --test mode. These are NOT part of the mirrored
# C table (chrome/cargo do not appear in class_rules); the --test fake
# workloads use them as their comm names. Deliberately chosen to not
# collide with anything real on a dev VM, so the test classifies only
# the two tasks it spawned. Merged into the effective table only when
# --test is given.
TEST_RULES = {
    "chrome": CLASS_INTERACTIVE,
    "cargo":  CLASS_BATCH,
}

# Fake-workload child code (run via `python3 -c`). Note:
# - ctypes prctl(PR_SET_NAME=15) renames this task; comm IS the rule key.
# - PR_SET_PDEATHSIG makes the kernel kill the child if the daemon is
#   SIGKILLed, so a dead daemon can never leave busy-loop orphans.
# - SIGINT/SIGTERM are ignored: ONLY the daemon decides when the test
#   workload dies (it terminates them explicitly at shutdown), which
#   also keeps Ctrl-C on a controlling terminal from racing the daemon
#   teardown. The name is passed as repr(bytes) via str.format.
TEST_CHILD_SRC = """
import ctypes, signal, time
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(1, signal.SIGKILL, 0, 0, 0)
if libc.prctl(15, ctypes.c_char_p({name}), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")
end = time.monotonic() + {secs}
while time.monotonic() < end:
    pass
"""

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

BPFTOOL = None          # resolved bpftool path (set in preflight)
exit_requested = False  # set by the SIGINT/SIGTERM handler only
last_signal = None


class DaemonError(Exception):
    """A bpftool step failed; the message always names the step."""


class SchedulerGone(Exception):
    """Raised inside the loop when the pins vanish mid-reconcile."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def log(message):
    """Daemon stdout line; flush=True so piped logs stay real-time."""
    print("foresight_daemon: " + message, flush=True)


def die(code, step, message):
    """Fatal, step-named error on stderr + non-zero exit."""
    print("foresight_daemon: FATAL [%s]: %s" % (step, message),
          file=sys.stderr, flush=True)
    sys.exit(code)


def pins_exist():
    """Both pinned maps must exist; this IS the scheduler-alive check."""
    return os.path.exists(PIN_TASK_CLASS) and os.path.exists(PIN_PID_PROBE)


def nap(seconds):
    """Sleep that a SIGINT can interrupt within <=0.2s (checked chunks)."""
    end = time.monotonic() + seconds
    while not exit_requested:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def _handle_signal(signum, _frame):
    """SIGINT/SIGTERM handler: only set the flag (re-entrant safe).

    SIGHUP is deliberately NOT handled: under nohup it stays SIG_IGN
    (inherited), which is exactly what a daemon should do when its
    terminal goes away.
    """
    global exit_requested, last_signal
    exit_requested = True
    last_signal = signum


# ---------------------------------------------------------------------------
# bpftool wrappers (timeout-bounded, never let bpftool output crash us)
# ---------------------------------------------------------------------------

def run_bpftool(args, step, timeout):
    """Run bpftool with a subcommand; return (ok, stderr_snippet).

    Raises DaemonError only for environmental failures (spawn/timeout);
    a non-zero bpftool exit code is reported via the return value so
    callers can decide whether it is fatal.
    """
    try:
        proc = subprocess.run([BPFTOOL] + args, capture_output=True,
                               timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DaemonError("%s: bpftool timed out after %ss" % (step, timeout))
    except OSError as exc:
        raise DaemonError("%s: could not run bpftool (%s)" % (step, exc))
    if proc.returncode == 0:
        return True, None
    err = proc.stderr.decode("utf-8", "replace").strip()
    return False, err or ("bpftool exit code %d" % proc.returncode)


def parse_hex_field(entry, field, step):
    """Decode one bpftool-JSON key/value field into raw bytes.

    Verified format (bpftool v7.7.0): a LIST of "0xNN" strings, e.g.
    ["0x64","0x70",...]. A single hex string ("6470..." or "64 70") is
    also accepted so a different bpftool version cannot break us.
    """
    raw = entry.get(field)
    if isinstance(raw, list):
        try:
            return bytes(int(tok, 16) for tok in raw)
        except (TypeError, ValueError) as exc:
            raise DaemonError("%s: bad hex byte list in field '%s': %s"
                               % (step, field, exc))
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw.replace(" ", "").replace("\t", ""))
        except ValueError as exc:
            raise DaemonError("%s: bad hex string in field '%s': %s"
                              % (step, field, exc))
    raise DaemonError("%s: bpftool JSON entry lacks field '%s'"
                      % (step, field))


def dump_map_entries(pin, step):
    """`bpftool -j map dump pinned <pin>` -> parsed JSON array."""
    try:
        proc = subprocess.run(
            [BPFTOOL, "-j", "map", "dump", "pinned", pin],
            capture_output=True, timeout=BPFTOOL_DUMP_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise DaemonError("%s: bpftool dump timed out after %ss"
                          % (step, BPFTOOL_DUMP_TIMEOUT))
    except OSError as exc:
        raise DaemonError("%s: could not run bpftool (%s)" % (step, exc))
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise DaemonError("%s: bpftool dump failed (rc=%d): %s"
                         % (step, proc.returncode, err))
    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DaemonError("%s: bpftool emitted unparseable JSON: %s"
                          % (step, exc))
    if not isinstance(data, list):
        raise DaemonError("%s: expected a JSON array, got %s"
                          % (step, type(data).__name__))
    return data


def _show_map_id(pin, step):
    """Map identity (bpftool 'id') - used to detect scheduler restarts."""
    try:
        proc = subprocess.run(
            [BPFTOOL, "-j", "map", "show", "pinned", pin],
            capture_output=True, timeout=BPFTOOL_SHOW_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise DaemonError("%s: bpftool show timed out" % step)
    except OSError as exc:
        raise DaemonError("%s: could not run bpftool (%s)" % (step, exc))
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise DaemonError("%s: bpftool show failed (rc=%d): %s"
                          % (step, proc.returncode, err))
    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DaemonError("%s: unparseable map show JSON: %s" % (step, exc))
    if isinstance(data, list):  # defensive: some versions emit an array
        if not data:
            raise DaemonError("%s: empty map show result" % step)
        data = data[0]
    if not isinstance(data, dict) or "id" not in data:
        raise DaemonError("%s: no 'id' in map show result" % step)
    return int(data["id"])


def update_task_class(gpid, cls):
    """Write one classification: key = LE u32 global pid, value = u8 class.

    Command line form (verified live): ONE ARGV TOKEN PER BYTE, e.g.
    ... key hex 9c 01 00 00 value hex 01
    """
    key = gpid.to_bytes(4, "little")
    args = ["map", "update", "pinned", PIN_TASK_CLASS,
            "key", "hex"] + ["%02x" % b for b in key] + \
           ["value", "hex", "%02x" % cls]
    return run_bpftool(args,
                       "task_class update (global_pid=%d class=%d)"
                       % (gpid, cls), BPFTOOL_UPDATE_TIMEOUT)


def delete_task_class(gpid):
    """Remove a classification the daemon owns (task gone / comm changed)."""
    key = gpid.to_bytes(4, "little")
    args = ["map", "delete", "pinned", PIN_TASK_CLASS,
            "key", "hex"] + ["%02x" % b for b in key]
    return run_bpftool(args, "task_class delete (global_pid=%d)" % gpid,
                       BPFTOOL_UPDATE_TIMEOUT)


# ---------------------------------------------------------------------------
# Offset discovery
# ---------------------------------------------------------------------------

def offset_sanity_max():
    """Upper sanity bound for a measured offset: the live pid_max.

    A real offset is always < /proc/sys/kernel/pid_max:
    kernel-global pids are drawn from [1, pid_max) and the offset is
    (global - namespaced) with namespaced >= 1. The bound is read
    live per attempt (reviewer NOTE: the old hardcoded OFFSET_MAX of
    10000 was wrong - long sessions can legitimately exceed it).
    Falls back to the 64-bit kernel default if the sysctl is
    unreadable.
    """
    try:
        with open("/proc/sys/kernel/pid_max", "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return PID_MAX_FALLBACK


def sweep_stale_probes():
    """Remove /tmp/fsxprobe_* left by a SIGKILLed previous run.

    Unlinking a probe binary that a live process already exec'd is
    harmless on Linux (the inode lives until the last fd closes), so
    this is safe even if another discovery is in flight. The probe
    processes themselves self-exit after PROBE_LIFETIME_S.
    """
    stale = glob.glob("/tmp/" + PROBE_PREFIX + "*")
    for path in stale:
        try:
            os.unlink(path)
            log("offset discovery: swept stale probe file %s" % path)
        except OSError:
            pass  # best-effort by definition
    return len(stale)


def _stop_probe(procs, paths, names):
    """finally-block cleanup: kill probes, unlink files, drop map entries.

    Everything here is best-effort BY DESIGN: this runs in a finally
    block, so an exception escaping it would REPLACE the in-flight
    result (the original bug or the good offset). Hence every step is
    individually guarded and can only log, never raise.
    """
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.terminate()
        except OSError:
            pass  # already dead - fine
    for proc in procs:
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            pass
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass
    for name in names:
        # NUL-pad the comm to the full char[16] map key, exactly as the
        # kernel-side bpf_get_current_comm() recorded it.
        comm16 = name.encode() + b"\x00" * (TASK_COMM_LEN - len(name))
        args = ["map", "delete", "pinned", PIN_PID_PROBE,
                "key", "hex"] + ["%02x" % b for b in comm16]
        try:
            run_bpftool(args, "pid_probe entry cleanup (%s)" % name,
                        BPFTOOL_UPDATE_TIMEOUT)
        except DaemonError as exc:
            log("offset discovery: could not delete probe entry for "
                "'%s' (%s) - harmless, names are unique per run and the "
                "map dies with the scheduler" % (name, exc))
        # Best-effort: a surviving entry is harmless - names are unique
        # per run and the whole map dies with the scheduler.


def _offset_attempt(quiet_launch):
    """One offset measurement: two probes that must agree.

    Returns (offset, description), or None if this attempt did not
    produce an agreeing, sane probe pair (the caller decides whether
    to retry). Raises SchedulerGone if the scheduler pins vanish while
    probing - the pin lifecycle contract applies at ANY time. On
    success in quiet mode nothing is logged, so the periodic loop
    rechecks stay invisible unless something actually changes.
    """
    # Unique 15-char probe names; "fsxprobe_" + 6 random chars. Names
    # must be unique per run: a collision with a stale pid_probe entry
    # would poison the measurement with a foreign global pid.
    names = []
    while len(names) < PROBE_PROBES_PER_ATTEMPT:
        cand = PROBE_PREFIX + "".join(
            random.choices(PROBE_ALPHABET, k=PROBE_SUFFIX_LEN))
        if cand not in names:
            names.append(cand)
    procs = []
    paths = []
    try:
        # Copy /bin/sleep under the probe name and launch it for
        # ~PROBE_LIFETIME_S: the exec tracepoint fires and records
        # comm=probe name -> kernel-global pid in pid_probe.
        for name in names:
            path = "/tmp/" + name
            shutil.copyfile(PROBE_SRC, path)
            os.chmod(path, 0o755)
            paths.append(path)
        for path in paths:
            procs.append(subprocess.Popen(
                [path, str(PROBE_LIFETIME_S)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL))
        ns_pids = [p.pid for p in procs]
        if not quiet_launch:
            log("offset discovery: probes %s launched (namespaced pids "
                "%s); polling pid_probe"
                % (", ".join(names), ", ".join(str(p) for p in ns_pids)))

        want = {name.encode(): ns for name, ns in zip(names, ns_pids)}
        seen = {}  # comm bytes -> global pid from the map
        deadline = time.monotonic() + PROBE_POLL_WINDOW_S
        while (time.monotonic() < deadline
               and len(seen) < len(want) and not exit_requested):
            if not pins_exist():
                # Pin lifecycle contract: the scheduler stopped under
                # us; our callers turn this into a clean exit 0.
                raise SchedulerGone()
            try:
                entries = dump_map_entries(
                    PIN_PID_PROBE, "pid_probe dump (offset discovery)")
            except DaemonError as exc:
                log("offset discovery: %s; will keep polling" % exc)
                entries = []
            for entry in entries:
                comm = parse_hex_field(entry, "key",
                                       "pid_probe dump").rstrip(b"\x00")
                if comm in want and comm not in seen:
                    gpid = int.from_bytes(
                        parse_hex_field(entry, "value", "pid_probe dump"),
                        "little")  # x86-64: raw LE memory image
                    seen[comm] = gpid
            if len(seen) < len(want):
                time.sleep(PROBE_POLL_INTERVAL_S)

        if exit_requested or len(seen) != len(want):
            if not exit_requested:
                missing = [n for n in names if n.encode() not in seen]
                log("offset discovery: only %d/%d probes appeared in "
                    "pid_probe within %.0fs (missing: %s)"
                    % (len(seen), len(want), PROBE_POLL_WINDOW_S,
                       ", ".join(missing)))
            return None

        pairs = []
        offsets = set()
        for name, ns in zip(names, ns_pids):
            gpid = seen[name.encode()]
            pairs.append((name, ns, gpid))
            offsets.add(gpid - ns)
        desc = "; ".join("'%s' ns=%d global=%d" % (n, ns, gp)
                         for n, ns, gp in pairs)
        if len(offsets) != 1:
            # Two probes measured seconds apart with unique names MUST
            # agree; a mismatch means a foreign entry collided or the
            # map is unhealthy. Never trust a lone reading then.
            log("offset discovery: probes DISAGREE (%s); attempt "
                "discarded" % desc)
            return None
        offset = offsets.pop()
        bound = offset_sanity_max()
        if not (0 <= offset < bound):
            log("offset discovery: insane offset %d (%s); sanity bound "
                "is 0 <= offset < pid_max = %d; attempt discarded"
                % (offset, desc, bound))
            return None
        return offset, desc
    finally:
        # Runs on success, failure, signal and SchedulerGone alike:
        # kill the probes, unlink the files, drop the map entries.
        _stop_probe(procs, paths, names)


def discover_offset():
    """Startup offset discovery: a couple of retrying attempts, then a
    loud fatal (exit 4). Returns the offset, or None if a signal asked
    us to stop before any attempt succeeded."""
    if not os.path.exists(PROBE_SRC):
        die(4, "offset discovery", "probe source %s not found" % PROBE_SRC)
    for attempt in range(1, PROBE_ATTEMPTS + 1):
        if exit_requested:
            return None
        if attempt > 1:
            log("offset discovery: retrying (attempt %d/%d)"
                % (attempt, PROBE_ATTEMPTS))
        result = _offset_attempt(quiet_launch=False)
        if result is not None:
            offset, desc = result
            log("offset discovery: %s" % desc)
            log("offset discovery: probes agree; live namespaced-pid -> "
                "kernel-global-pid offset is +%d" % offset)
            return offset
    die(4, "offset discovery",
        "no attempt produced an agreeing, sane probe pair after %d "
        "attempts - is the scheduler's pid_probe tracepoint attached "
        "and healthy?" % PROBE_ATTEMPTS)


def refresh_offset():
    """Loop-side drift guard: one quiet re-measure per recheck cycle.

    Returns (offset, desc), or None if this recheck failed (the loop
    retries next cycle and escalates after RECHECK_GIVEUP). May raise
    SchedulerGone (scheduler stopped) or DaemonError (bpftool broke);
    both are handled by the loop's existing exception ladder.
    """
    if exit_requested:
        return None
    return _offset_attempt(quiet_launch=True)


def _drop_all_state(state, failcount, abandoned):
    """Delete every tracked entry from task_class and reset bookkeeping.

    Callers (reviewer findings):
      - the SIGINT/SIGTERM exit path (SHOULD-FIX): a clean shutdown
        must delete what this daemon generation wrote, else its
        entries accumulate in the scheduler's map across daemon
        generations (live-observed stale pids persisting after clean
        exits);
      - the map-id-change path (NOTE): best-effort-delete our recorded
        keys from the CURRENT map before clearing bookkeeping - after
        a scheduler restart the pins target a fresh map, so most
        deletes hit ENOENT (harmless), but a key that does exist was
        written against this very map and would otherwise be orphaned
        with no owner left to reap it.
    Each entry is deleted by the global pid RECORDED at classification
    time - the key this daemon actually wrote (sticky per-task offset,
    see header). Best-effort BY DESIGN: this runs on exit paths where
    a raise would mask the real exit; a failed delete means the
    scheduler/map went away, and with it our entries. Only entries in
    `state` are touched (ours) - never the maintainer's Phase 0 CLI
    seeds.
    """
    for ns_pid in sorted(state):
        gpid = state[ns_pid][0]
        ok, err = delete_task_class(gpid)
        if not ok:
            log("state cleanup: delete of global_pid=%d (ns_pid=%d) "
                "failed (%s) - harmless if the scheduler stopped; the "
                "map dies with it" % (gpid, ns_pid, err))
    state.clear()
    failcount.clear()
    abandoned.clear()


# ---------------------------------------------------------------------------
# Classification loop
# ---------------------------------------------------------------------------

def scan_proc_comms():
    """One /proc sweep: {namespaced pid -> comm}.

    /proc top-level numeric entries are TASK-granular (threads, not
    just leaders), which matches the scheduler: task_class is keyed by
    the task's pid (what ps calls a tid). Tasks that vanish mid-scan
    are skipped silently - normal churn, next pass sees their heirs.
    """
    out = {}
    for comm_path in glob.glob("/proc/[0-9]*/comm"):
        parts = comm_path.split("/")
        # "/proc/123/comm" -> ["", "proc", "123", "comm"]
        try:
            ns_pid = int(parts[2])
            with open(comm_path, "rb") as fh:
                comm = fh.read().strip(b"\n").decode("utf-8", "replace")
        except (ValueError, OSError):
            continue
        out[ns_pid] = comm
    return out


def reconcile(rules, offset, state, failcount, abandoned, kernel_managed=None):
    """Bring task_class in line with what /proc says, printing changes only.

    state:      {namespaced pid -> (global pid written, class)} - the
                global pid is RECORDED at classification time and is
                sticky for the task's whole life (reviewer BLOCKING
                fix: a task's global pid never changes, so the
                recorded key stays correct even after the live offset
                drifts; see header)
    failcount:  {namespaced pid -> consecutive update failures}
    abandoned:  {namespaced pid} we gave up updating this run
    kernel_managed: (Phase 2) mutable set of KERNEL-GLOBAL pids the
                kernel behavior-demoted (drained from the `demotions`
                map). Classification writes for these pids are SKIPPED
                - the kernel owns them now - and entries leave the set
                when the pid disappears from /proc. None (the default)
                behaves as an empty set, so pre-Phase 2 callers work.
    """
    if kernel_managed is None:
        kernel_managed = set()
    comms = scan_proc_comms()
    desired = {}
    for ns_pid, comm in comms.items():
        cls = rules.get(comm)
        if cls is not None:
            desired[ns_pid] = (cls, comm)

    # Phase 2 (behavior-demotion listener bookkeeping): a kernel-managed
    # pid leaves the skip set once it disappears from /proc, so a
    # recycled global pid is never blocked forever. The "still alive"
    # candidates are the RECORDED global pids of tracked tasks (exact -
    # a task's global pid never changes, see header) plus the cohort
    # arithmetic ns_pid + live offset for tasks never tracked
    # (approximate: the same one-window aliasing residual the Phase 1
    # limitations already document; an untracked entry can also expire
    # early right after an offset drift, which self-heals - the kernel
    # re-demotes and a fresh event re-registers the pid).
    if kernel_managed:
        candidates = {rec[0] for rec in state.values()}
        candidates.update(ns + offset for ns in comms)
        for gpid in sorted(kernel_managed - candidates):
            kernel_managed.discard(gpid)
            log("kernel-managed global pid %d left /proc; releasing "
                "the classification skip" % gpid)

    # 1) New or changed classifications.
    for ns_pid in sorted(desired):
        # Reviewer SHOULD-FIX: check the exit flag between per-task
        # iterations - per-entry bpftool subprocess calls used to
        # ignore it entirely (SIGTERM exit latency ~6.4s observed,
        # worst case minutes). Abort here; partial passes self-heal
        # (the next pass - or the shutdown drop-all - completes it).
        if exit_requested:
            return
        if ns_pid in abandoned:
            continue
        cls, comm = desired[ns_pid]
        entry = state.get(ns_pid)
        if entry is not None and entry[1] == cls:
            continue  # unchanged: stay silent (mandate: print changes only)
        # Key to write: an already-tracked task keeps the global pid
        # RECORDED when it was classified - a task's global pid never
        # changes, and re-keying with the (larger) live offset would
        # overshoot it (reviewer BLOCKING fix; see header). Only a
        # task first seen now is keyed with the current offset.
        gpid = entry[0] if entry is not None else ns_pid + offset
        # Phase 2 (THE cross-component subtlety): the kernel behavior-
        # demoted this task (event drained from `demotions` this same
        # pass); the classifier MUST NOT write it again. Without this
        # skip the comm-based re-classification below would overwrite
        # the kernel's demotion every 2s cycle and the kernel would
        # re-demote forever (classify interactive -> kernel demotes ->
        # daemon re-classifies interactive -> ...). The comparison is in
        # GLOBAL pids - the demotions key space, same as task_class -
        # against the exact global pid this pass would write. A
        # comm-driven class CHANGE for a kernel-managed pid is likewise
        # deferred until the pid leaves /proc: v1 hands the pid to the
        # kernel wholesale rather than second-guessing the demotion.
        if gpid in kernel_managed:
            continue
        ok, err = update_task_class(gpid, cls)
        if ok:
            state[ns_pid] = (gpid, cls)
            failcount.pop(ns_pid, None)
            log("classify comm='%s' ns_pid=%d -> global_pid=%d "
                "class %d (%s) [%d tracked]"
                % (comm, ns_pid, gpid, cls, CLASS_NAMES[cls], len(state)))
        else:
            if not pins_exist():
                raise SchedulerGone()
            fails = failcount.get(ns_pid, 0) + 1
            failcount[ns_pid] = fails
            if fails >= UPDATE_GIVEUP_AFTER:
                abandoned.add(ns_pid)
                log("task_class update failed %d times for ns_pid=%d "
                    "comm='%s'; giving up on it this run (last: %s)"
                    % (fails, ns_pid, comm, err))
            else:
                log("task_class update failed for ns_pid=%d "
                    "comm='%s' (attempt %d, will retry; %s)"
                    % (ns_pid, comm, fails, err))

    # 2) Reaps: entries we own whose task died or whose comm stopped
    #    matching. Deleting matters: pid reuse would otherwise let a
    #    stale entry classify an innocent new task. The delete uses
    #    the RECORDED global pid - sticky for the task's life
    #    (reviewer BLOCKING fix). We only ever delete entries in
    #    `state` (i.e. ours), never the maintainer's Phase 0 CLI seeds.
    for ns_pid in sorted(set(state) - set(desired)):
        if exit_requested:
            return  # same SHOULD-FIX as the loop above
        gpid, cls = state[ns_pid]
        ok, err = delete_task_class(gpid)
        if not ok and not pins_exist():
            raise SchedulerGone()
        del state[ns_pid]
        failcount.pop(ns_pid, None)
        if ok:
            log("reap global_pid=%d (was class %d (%s)): task gone or "
                "comm changed; removed from map [%d tracked]"
                % (gpid, cls, CLASS_NAMES[cls], len(state)))
        else:
            # Entry probably vanished with a scheduler restart; tracking
            # is dropped either way so the next pass re-decides.
            log("reap global_pid=%d (was class %d): map delete failed "
                "(%s); dropping tracking only" % (gpid, cls, err))


def check_map_ids(initial_ids, state, failcount, abandoned, phase2=None):
    """Detect a scheduler restart that was too fast for the pins check.

    A fresh scheduler instance pins NEW map objects; bpftool's map id
    changes. On change, best-effort-delete our tracked keys from the
    CURRENT map and clear bookkeeping (reviewer NOTE): the fresh map
    is normally empty, so most deletes hit ENOENT - harmless - but a
    key that does exist was written against this very map and would
    otherwise be orphaned with no owner left to reap it. Every
    classification is then re-written from scratch.

    Phase 2 (phase2 given): the restart also resets ALL Phase 2
    bookkeeping - the fresh stats counters start at zero (old
    EWMA/streak state describes a dead instance), the fresh loader
    re-seeded knobs (re-adopted read-only on the next controller
    cycle), and the fresh demotions map is empty (kernel_managed dies
    with the old instance; still-demoted tasks re-register through
    fresh events).
    """
    changed = None
    for pin, old_id in initial_ids.items():
        new_id = _show_map_id(pin, "map id liveness check")
        if new_id != old_id:
            changed = (pin, old_id, new_id)
            initial_ids[pin] = new_id
    if changed is not None:
        pin, old_id, new_id = changed
        log("scheduler restarted under us (map %s id %d -> %d); "
            "best-effort-deleting %d tracked entries and re-classifying "
            "from scratch"
            % (os.path.basename(pin), old_id, new_id, len(state)))
        _drop_all_state(state, failcount, abandoned)
        if phase2 is not None:
            # Phase 2: fresh maps on every axis - see docstring.
            phase2.reset()


# ---------------------------------------------------------------------------
# Phase 2: adaptive-knob controller + behavior-demotion listener
# ---------------------------------------------------------------------------

class KnobController:
    """Phase 2 hysteresis state machine over the interactive enqueue
    rate. PURE LOGIC - no bpftool, no clocks: the loop feeds it one
    rate observation per cycle and executes any returned action. That
    keeps the whole policy unit-testable offline
    (foresight_phase2_tests.py).

    Rules (see the Phase 2 header section and the constants above):
      - EWMA (alpha 0.3) over the interactive lane's enqueue rate;
        the first observation seeds it.
      - Warmup: the first KNOB_WARMUP_SAMPLES observations are
        observation-only - no streaks accumulate, no rule may fire.
      - HOT:  ewma > 50/s on 3 consecutive evaluated cycles ->
              interactive_slice_ns = 10ms (INTERACTIVE_SLICE_FAST).
      - COOL: ewma < 25/s on 5 consecutive evaluated cycles ->
              interactive_slice_ns = 20ms (INTERACTIVE_SLICE_DEFAULT).
      - Only actual CHANGES return an action: while the knob already
        sits at the target value, sustained rates stay silent. A
        FAILED write keeps the old belief, so the same rule re-fires
        on later cycles - the streak IS the retry mechanism.
    """

    def __init__(self):
        self.ewma = None          # None until the first observation
        self.samples = 0          # rate observations incorporated
        self.hot_streak = 0       # consecutive evaluated cycles > 50/s
        self.cool_streak = 0      # consecutive evaluated cycles < 25/s
        self.slice_ns = INTERACTIVE_SLICE_DEFAULT  # last CONFIRMED value
        self.synced = False       # True once adopted from the live map

    def reset(self):
        """Scheduler restart (fresh maps): drop the baseline AND the
        knob belief. Restarting the warmup is deliberate - the fresh
        counters start at zero, so old EWMA/streak state describes a
        scheduler instance that no longer exists."""
        self.ewma = None
        self.samples = 0
        self.hot_streak = 0
        self.cool_streak = 0
        self.slice_ns = INTERACTIVE_SLICE_DEFAULT
        self.synced = False

    def adopt(self, slice_ns):
        """Believe the value the live map holds (startup, or after a
        detected scheduler restart). Phase 2 never WRITES here: a
        previous daemon generation may have left the knob at 10ms,
        and assuming the loader's 20ms seed would print a bogus 'old
        value' on the first rule firing."""
        self.slice_ns = slice_ns
        self.synced = True

    def apply(self, slice_ns):
        """Confirm one successful knob write. Called ONLY on bpftool
        success: on failure the belief keeps the old value so the
        rule re-fires next cycle (natural, self-healing retry)."""
        self.slice_ns = slice_ns

    def observe(self, rate):
        """Feed one interactive-rate observation. Returns None, or an
        action ("hot"/"cool", target_slice_ns, consecutive_cycles,
        ewma) when a rule fires an actual change."""
        # EWMA update: first observation seeds; afterwards the
        # standard blend with alpha = KNOB_EWMA_ALPHA = 0.3.
        if self.ewma is None:
            self.ewma = float(rate)
        else:
            self.ewma = (KNOB_EWMA_ALPHA * rate
                         + (1.0 - KNOB_EWMA_ALPHA) * self.ewma)
        self.samples += 1
        # Baseline warmup (Phase 2 rule): the first KNOB_WARMUP_SAMPLES
        # observations are observation-only. Streaks only accumulate
        # on evaluated cycles, so a rule needs its full consecutive
        # run AFTER warmup ends.
        if self.samples <= KNOB_WARMUP_SAMPLES:
            return None
        if self.ewma > KNOB_HOT_RATE:
            self.hot_streak += 1
            self.cool_streak = 0
            if (self.hot_streak >= KNOB_HOT_STREAK
                    and self.slice_ns != INTERACTIVE_SLICE_FAST):
                return ("hot", INTERACTIVE_SLICE_FAST,
                        self.hot_streak, self.ewma)
        elif self.ewma < KNOB_COOL_RATE:
            self.cool_streak += 1
            self.hot_streak = 0
            if (self.cool_streak >= KNOB_COOL_STREAK
                    and self.slice_ns != INTERACTIVE_SLICE_DEFAULT):
                return ("cool", INTERACTIVE_SLICE_DEFAULT,
                        self.cool_streak, self.ewma)
        else:
            # Deadband (25/s <= ewma <= 50/s): both consecutive runs
            # break. Strict comparisons per the Phase 2 contract.
            self.hot_streak = 0
            self.cool_streak = 0
        return None


class Phase2State:
    """All mutable Phase 2 bookkeeping in one object, so the detected
    scheduler-restart path (check_map_ids) can reset it atomically."""

    def __init__(self):
        # The adaptive-knob controller (EWMA + hysteresis machine).
        self.knob = KnobController()
        # KERNEL-GLOBAL pids the kernel behavior-demoted. reconcile()
        # MUST skip these - see the Phase 2 header section for why the
        # skip is the difference between a clean handoff and infinite
        # 2s-cycle flapping. Key space: kernel-global pids, the same
        # one task_class and the demotions map use.
        self.kernel_managed = set()
        # gpid -> ts_ns of the last event announced for that pid: dedups
        # the BEHAVIOR DEMOTION line while a demotions delete keeps
        # failing (the entry stays in the map and re-dumps next cycle).
        self.seen_demotions = {}
        # Previous cycle's stats snapshot and its monotonic timestamp:
        # rate denominators are MEASURED wall time, not the nominal 2s.
        self.last_stats = None
        self.last_stats_at = None
        # Completed controller cycles (drives the ~30s visibility line;
        # deliberately NOT reset on restart - it is only a cadence).
        self.cycles = 0
        # Latched when knobs[0] is absent or not contract-shaped: knob
        # writes stop for the rest of the run rather than corrupt a
        # struct whose layout we do not recognize. Cleared by reset().
        self.writes_disabled = False
        # One-shot guard for the "rule fired but writes are disabled"
        # line (the rule keeps re-firing; it must not re-announce).
        self.disabled_announced = False

    def reset(self):
        """Scheduler restart (fresh map ids): fresh bookkeeping. The
        fresh demotions map is empty, so kernel_managed dies with the
        old instance - a still-demoted task re-demotes under the new
        one and re-registers itself through a fresh event. The knob
        controller re-adopts the value the fresh loader seeded."""
        self.knob.reset()
        self.kernel_managed.clear()
        self.seen_demotions.clear()
        self.last_stats = None
        self.last_stats_at = None
        self.writes_disabled = False
        self.disabled_announced = False


def _parse_stats_entries(entries, step):
    """Phase 2 (PURE, unit-tested): parsed bpftool-JSON dump entries of
    the stats map -> {class key: u64 counter}. Reuses the existing
    bpftool-JSON helpers (parse_hex_field).

    The contract is a plain ARRAY (key u32 0..2 -> u64; see
    foresight_sched.bpf.c), so each value is one 8-byte counter.
    Defensive extra: the C loader deliberately tolerates a PERCPU_ARRAY
    stats map as well (its read_stats sums every CPU), so a value blob
    whose length is a multiple of 8 is SUMMED chunk by chunk instead of
    trusting one CPU's counter - the daemon's rate math then matches
    the loader's own accounting. Malformed keys/values are skipped,
    never fatal: an ARRAY dump always contains all three keys anyway.
    """
    out = {}
    for entry in entries:
        key = parse_hex_field(entry, "key", step)
        raw = parse_hex_field(entry, "value", step)
        if len(key) != 4:
            continue  # not a u32 class key
        idx = int.from_bytes(key, "little")
        if idx not in (CLASS_NORMAL, CLASS_INTERACTIVE, CLASS_BATCH):
            continue
        if len(raw) >= 8 and len(raw) % 8 == 0:
            out[idx] = sum(int.from_bytes(raw[i:i + 8], "little")
                           for i in range(0, len(raw), 8))
    return out


def read_stats_counters():
    """Phase 2: one pinned-stats dump -> {class key: u64 counter}."""
    step = "stats dump (knob controller)"
    return _parse_stats_entries(dump_map_entries(PIN_STATS, step), step)


def _parse_demotion_entry(entry):
    """Phase 2 (PURE, unit-tested): one parsed bpftool-JSON entry of
    the demotions map -> (pid, ts_ns, from_class, to_class, streak,
    raw_key_bytes), or None when the entry violates the contract (bad
    key length, or a value shorter than the 12-byte struct body). The
    caller must NOT adopt a None; it deletes the raw entry instead so a
    malformed event can neither steer the classifier nor spam the log
    forever. The map key is the task's KERNEL-GLOBAL pid - the same key
    space as task_class (the BPF side cannot see pids namespace-
    locally); the listener never translates it.
    """
    raw_key = parse_hex_field(entry, "key", "demotions dump")
    raw_val = parse_hex_field(entry, "value", "demotions dump")
    if len(raw_key) != 4 or len(raw_val) < DEMOTION_VALUE_MIN:
        return None
    pid = int.from_bytes(raw_key, "little")
    ts_ns, from_cls, to_cls, streak = struct.unpack_from(
        DEMOTION_VALUE_FMT, raw_val, 0)
    return pid, ts_ns, from_cls, to_cls, streak, raw_key


def knobs_rebuild(raw, new_interactive_slice_ns):
    """Phase 2 (PURE, unit-tested): the read-modify-write encoding.

    Given the exact 24-byte knobs[0] memory image currently in the
    map, return that image with interactive_slice_ns replaced and
    EVERY other field - batch_slice_ns, demote_streak, _pad - copied
    through bit for bit. Phase 2 v1 owns exactly one field; zeroing or
    re-packing any other would silently change kernel behavior the
    daemon has no mandate over. LE "<QQII" is the x86-64 raw memory
    image of the C struct { u64; u64; u32; u32; } - natural alignment,
    no holes, sizeof 24 (verified byte for byte in the offline tests).
    """
    _old_interactive, batch_ns, demote_streak, pad = struct.unpack(
        KNOBS_VALUE_FMT, raw)
    return struct.pack(KNOBS_VALUE_FMT, new_interactive_slice_ns,
                       batch_ns, demote_streak, pad)


def read_knobs(step):
    """Phase 2: dump knobs[0] -> ((interactive_slice_ns,
    batch_slice_ns, demote_streak, _pad), raw_bytes), or None when the
    entry is absent or its size is not exactly the contract's 24
    bytes. Returning None instead of guessing is the whole point: the
    caller must refuse to write a struct it cannot parse.
    """
    for entry in dump_map_entries(PIN_KNOBS, step):
        key = parse_hex_field(entry, "key", step)
        if len(key) != 4 or int.from_bytes(key, "little") != 0:
            continue  # the contract has exactly one knob, at key 0
        raw = parse_hex_field(entry, "value", step)
        if len(raw) != KNOBS_VALUE_SIZE:
            log("knobctl: knobs[0] value is %d bytes, contract says %d "
                "(struct { u64 interactive_slice_ns; u64 batch_slice_ns; "
                "u32 demote_streak; u32 _pad; }); refusing all knob "
                "writes this run" % (len(raw), KNOBS_VALUE_SIZE))
            return None
        return struct.unpack(KNOBS_VALUE_FMT, raw), raw
    return None


def write_knob_interactive_slice(new_slice_ns):
    """Phase 2: the ONLY knobs write in the daemon - a full-struct
    read-modify-write of knobs[0] with interactive_slice_ns swapped
    (batch_slice_ns, demote_streak and _pad ride along untouched, via
    knobs_rebuild). Returns True only on a confirmed bpftool success.

    Concurrency (reviewer): the contract gives the knobs map exactly
    two writers - the loader's one-time seed at scheduler start, and
    this daemon. The kernel only READS knobs and reports through
    `demotions`, so a torn read-modify-write interleaving is
    impossible in v1; if a future phase adds a second runtime writer,
    this needs a compare-and-swap discipline, not silence.
    """
    step = "knobs RMW (interactive_slice_ns)"
    got = read_knobs(step)
    if got is None:
        # read_knobs already said why (absent or wrong size); never
        # fabricate a struct: we do not own the other fields.
        return False
    raw_new = knobs_rebuild(got[1], new_slice_ns)
    key = (0).to_bytes(4, "little")
    # Same verified argv discipline as update_task_class: ONE TOKEN
    # PER BYTE (see the bpftool FORMATS section of the header).
    args = ["map", "update", "pinned", PIN_KNOBS,
            "key", "hex"] + ["%02x" % b for b in key] + \
           ["value", "hex"] + ["%02x" % b for b in raw_new]
    ok, err = run_bpftool(args, step, BPFTOOL_UPDATE_TIMEOUT)
    if not ok:
        if not pins_exist():
            # Pin lifecycle contract: the scheduler stopped mid-write.
            raise SchedulerGone()
        log("knobctl: knobs update failed (%s); belief unchanged, the "
            "rule will retry while it still holds" % err)
    return ok


def _delete_demotion(raw_key, step):
    """Delete one demotions entry by its EXACT raw key bytes (works
    even for a malformed key). Not fatal on failure: drain_demotions
    dedups the announcement and the delete is retried next cycle."""
    args = ["map", "delete", "pinned", PIN_DEMOTIONS,
            "key", "hex"] + ["%02x" % b for b in raw_key]
    ok, err = run_bpftool(args, step, BPFTOOL_UPDATE_TIMEOUT)
    if not ok:
        if not pins_exist():
            raise SchedulerGone()  # pin lifecycle contract
        log("demotions: delete failed (%s); will retry next cycle" % err)


def drain_demotions(phase2):
    """Phase 2 behavior-demotion listener: dump the pinned `demotions`
    map; for EACH entry print one explainable line, adopt the pid into
    kernel_managed, then DELETE the entry - the event lifecycle is the
    daemon's job in userspace, the kernel never reclaims an entry.

    THE CROSS-COMPONENT SUBTLETY (Phase 2 rule): adopting the pid into
    kernel_managed is what stops the 2s-cycle flapping. Without the
    classifier-side skip this set drives, the daemon's comm-based
    re-classification would overwrite the kernel's demotion every
    cycle and the kernel would re-demote forever: classify
    interactive, kernel demotes, daemon re-classifies interactive, ...
    """
    # Housekeeping: seen_demotions only needs to cover pids that are
    # still kernel-managed (an expired pid that reappears comes with a
    # fresh ts anyway) - keeps the dedup memory bounded.
    for pid in list(phase2.seen_demotions):
        if pid not in phase2.kernel_managed:
            del phase2.seen_demotions[pid]
    for entry in dump_map_entries(PIN_DEMOTIONS, "demotions dump"):
        if exit_requested:
            break  # same signal discipline as reconcile's task loops
        parsed = _parse_demotion_entry(entry)
        if parsed is None:
            raw_key = parse_hex_field(entry, "key", "demotions dump")
            raw_val = parse_hex_field(entry, "value", "demotions dump")
            log("BEHAVIOR DEMOTION: contract violation (key %s, value "
                "%s); deleting the raw entry WITHOUT adopting it"
                % (raw_key.hex(), raw_val.hex()))
            _delete_demotion(raw_key, "demotions delete (raw entry)")
            continue
        pid, ts_ns, from_cls, to_cls, streak, raw_key = parsed
        if phase2.seen_demotions.get(pid) == ts_ns:
            # Same event as before (its delete failed and the kernel
            # has not written a new one): retry the delete, no
            # duplicate announcement.
            _delete_demotion(raw_key, "demotions delete (pid=%d)" % pid)
            continue
        # The mandated one line per event. ts_ns is printed exactly as
        # the kernel recorded it - its clock domain is the kernel's
        # choice and must not be reinterpreted here. Class names
        # render the canonical case as the exact contract text
        # "interactive -> batch"; an unexpected class value is still
        # printed truthfully rather than misnamed.
        log("BEHAVIOR DEMOTION: pid %d exhausted %d consecutive slices "
            "as %s -> %s (kernel-authoritative at %d)"
            % (pid, streak,
               CLASS_NAMES.get(from_cls, "class %d" % from_cls),
               CLASS_NAMES.get(to_cls, "class %d" % to_cls), ts_ns))
        phase2.kernel_managed.add(pid)
        phase2.seen_demotions[pid] = ts_ns
        _delete_demotion(raw_key, "demotions delete (pid=%d)" % pid)


def run_knob_cycle(phase2):
    """Phase 2 adaptive-knob controller: one invocation per loop pass.
    (1) once per scheduler instance, adopt the live knob value
    (read-only); (2) read stats; (3) turn counter deltas into per-lane
    enqueue rates over the MEASURED wall time since the last read;
    (4) feed the EWMA/hysteresis machine; (5) execute at most ONE knobs
    read-modify-write when it fires - there are no other knob writes.
    """
    if exit_requested:
        return
    phase2.cycles += 1
    if not phase2.knob.synced:
        got = read_knobs("knobs adoption read")
        if got is None:
            # Absent or not contract-shaped: latch writes off for this
            # run (classification is unaffected) rather than guess.
            phase2.writes_disabled = True
            log("knobctl: no contract-shaped knobs[0] to adopt; knob "
                "writes are DISABLED this run")
        else:
            phase2.knob.adopt(got[0][0])
            log("knobctl: adopted live interactive_slice_ns=%d from "
                "knobs[0] (read-only, no write)" % got[0][0])
    counters = read_stats_counters()
    now = time.monotonic()
    if phase2.last_stats is None or phase2.last_stats_at is None:
        # First read for this scheduler instance: baseline only, no
        # rate exists yet. The warmup observations start next cycle.
        phase2.last_stats = counters
        phase2.last_stats_at = now
        log("knobctl: stats baseline set (interactive=%d batch=%d); "
            "%d-observation warmup starts next cycle"
            % (counters.get(CLASS_INTERACTIVE, 0),
               counters.get(CLASS_BATCH, 0), KNOB_WARMUP_SAMPLES))
        return
    # MEASURED interval, never the nominal 2s: an offset-recheck pass
    # runs a probe pair with a 6s poll window, and a large demotion
    # backlog stretches a pass too - dividing those deltas by 2.0 would
    # overstate the rate up to ~4x and could fire the hot rule on a
    # perfectly quiet system.
    interval = now - phase2.last_stats_at
    if interval <= 0:
        interval = LOOP_INTERVAL_S  # monotonic misbehavior: nominal cadence
    delta_i = (counters.get(CLASS_INTERACTIVE, 0)
               - phase2.last_stats.get(CLASS_INTERACTIVE, 0))
    delta_b = (counters.get(CLASS_BATCH, 0)
               - phase2.last_stats.get(CLASS_BATCH, 0))
    phase2.last_stats = counters
    phase2.last_stats_at = now
    if delta_i < 0 or delta_b < 0:
        # u64 enqueue counters never decrease: a negative delta means
        # the stats map was reset or replaced underneath us (a
        # scheduler restart the map-id check has not seen yet, or a
        # reload of the stats map alone). Re-baseline and restart the
        # warmup rather than feed a nonsense negative rate into the
        # EWMA - same discipline as the map-id reset, self-triggered.
        log("knobctl: stats counters regressed (interactive delta=%d, "
            "batch delta=%d); re-baselining, warmup restarts"
            % (delta_i, delta_b))
        phase2.knob.reset()
        return
    rate_i = delta_i / interval
    rate_b = delta_b / interval
    action = phase2.knob.observe(rate_i)
    # Visibility: one line every ~30s, once when warmup completes, and
    # on every rule firing - enough to watch the controller work in
    # acceptance without per-cycle noise (the daemon prints changes).
    if (action is not None
            or phase2.cycles % KNOB_STATUS_EVERY == 0
            or phase2.knob.samples == KNOB_WARMUP_SAMPLES + 1):
        warm = ("warming %d/%d" % (phase2.knob.samples,
                                   KNOB_WARMUP_SAMPLES)
                if phase2.knob.samples <= KNOB_WARMUP_SAMPLES
                else "armed")
        log("knobctl: cycle %d: enqueue rates interactive=%.1f/s "
            "batch=%.1f/s; EWMA interactive=%.1f/s (%s); "
            "interactive_slice_ns=%d%s"
            % (phase2.cycles, rate_i, rate_b, phase2.knob.ewma, warm,
               phase2.knob.slice_ns,
               "; knob writes DISABLED (ABI mismatch)"
               if phase2.writes_disabled else ""))
    if action is None:
        return
    rule, target, streak, ewma = action
    if phase2.writes_disabled:
        if not phase2.disabled_announced:
            phase2.disabled_announced = True
            log("knobctl: %s rule fired (EWMA %.1f/s, %d consecutive "
                "cycles) but knob writes are disabled this run; later "
                "firings stay silent" % (rule, ewma, streak))
        return
    if write_knob_interactive_slice(target):
        old = phase2.knob.slice_ns
        phase2.knob.apply(target)
        # The ONE explainable line per actual change (Phase 2 rule):
        # old value, new value, the EWMA number, the rule that fired,
        # and the consecutive-cycle count. Nothing else is printed.
        log("knobctl: interactive_slice_ns %d -> %d (EWMA interactive "
            "rate %.1f/s; %s rule: %s for %d consecutive cycles)"
            % (old, target, ewma, rule,
               ("EWMA > %.0f/s" % KNOB_HOT_RATE) if rule == "hot"
               else ("EWMA < %.0f/s" % KNOB_COOL_RATE), streak))
    # else: write_knob_interactive_slice already logged the failure and
    # the belief is unchanged, so the rule re-fires and retries next
    # cycle while its conditions still hold.


# ---------------------------------------------------------------------------
# --test mode
# ---------------------------------------------------------------------------

def spawn_test_children():
    """Spawn the two fake workloads (chrome=interactive, cargo=batch).

    Each child renames ITSELF via prctl so the plain /proc scan picks
    it up through the same rules path as any real workload - the test
    therefore exercises the WHOLE daemon pipeline end to end.
    """
    children = []
    for comm, cls in (("chrome", CLASS_INTERACTIVE),
                      ("cargo", CLASS_BATCH)):
        code = TEST_CHILD_SRC.format(name=repr(comm.encode()),
                                     secs=TEST_CHILD_SECONDS)
        proc = subprocess.Popen(
            [sys.executable or "python3", "-c", code],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        log("--test: spawning fake workload pid=%d, comm->'%s', class %d "
            "(%s), busy-loop %ds"
            % (proc.pid, comm, cls, CLASS_NAMES[cls], TEST_CHILD_SECONDS))
        children.append({"proc": proc, "comm": comm, "cls": cls,
                         "reported": False})
    log("--test: the classification loop will pick them up within %.0fs; "
        "watch the scheduler's 'enq normal=X interactive=Y batch=Z' "
        "stats lines climb in BOTH lanes" % LOOP_INTERVAL_S)
    return children


def poll_test_children(children):
    """Reap (and report) test children that finished their busy-loop."""
    for child in children:
        if child["reported"]:
            continue
        rc = child["proc"].poll()
        if rc is not None:
            child["reported"] = True
            log("--test: fake workload comm='%s' (pid %d) exited rc=%s"
                % (child["comm"], child["proc"].pid, rc))


def kill_test_children(children):
    """Shutdown path: terminate, then kill, any test children still alive.

    Best-effort and exception-proof: this runs from main()'s finally
    block, where a stray exception would mask the daemon's real exit
    path. poll()/terminate() races are guarded (ProcessLookupError is
    an OSError subclass).
    """
    if not children:
        return
    for child in children:
        try:
            if child["proc"].poll() is None:
                child["proc"].terminate()
        except OSError:
            pass
    for child in children:
        try:
            child["proc"].wait(3)
        except subprocess.TimeoutExpired:
            try:
                child["proc"].kill()
            except OSError:
                pass
            try:
                child["proc"].wait(3)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            pass
    log("--test: all fake workloads stopped")


# ---------------------------------------------------------------------------
# Preflight and main
# ---------------------------------------------------------------------------

USAGE = "usage: foresight_daemon.py [--test]  (--test: spawn fake chrome/" \
        "cargo workloads; see header docstring)"


def locate_bpftool():
    """Find bpftool: known paths first (kernel-tree + sched_ext build),
    then PATH. Exits 3 with a clear message if nowhere."""
    global BPFTOOL
    for cand in BPFTOOL_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            BPFTOOL = cand
            log("preflight: bpftool found at %s" % cand)
            return
    on_path = shutil.which("bpftool")
    if on_path:
        BPFTOOL = on_path
        log("preflight: bpftool found on PATH at %s" % on_path)
        return
    die(3, "preflight",
        "bpftool not found (tried %s, then PATH); build it in the "
        "kernel tree (make -C tools/bpf/bpftool) or install it"
        % ", ".join(BPFTOOL_CANDIDATES))


def preflight():
    """Pins must exist (scheduler running) and we must be root."""
    if os.geteuid() != 0:
        die(5, "preflight",
            "not running as root (euid=%d); the pinned maps under %s "
            "are root-owned" % (os.geteuid(), PIN_DIR))
    # Phase 2: the controller and the demotion listener add three
    # pinned maps to the contract (stats, knobs, demotions). Preflight
    # demands ALL five with the same "is the scheduler running?"
    # discipline (exit 2): a Phase 1-only scheduler must be refused
    # outright, not quietly half-driven by a Phase 2 daemon.
    for pin in (PIN_TASK_CLASS, PIN_PID_PROBE,
                PIN_STATS, PIN_KNOBS, PIN_DEMOTIONS):
        if not os.path.exists(pin):
            die(2, "preflight",
                "pin %s does not exist - is the scheduler running? "
                "(also: WSL2 gives each wsl session its own mount "
                "namespace; run this daemon where the scheduler was "
                "started, e.g. via "
                "'nsenter -t $(pgrep -x foresight_sched) -m -- python3 "
                "foresight_daemon.py')" % pin)
    log("preflight: pins present: %s, %s" % (PIN_TASK_CLASS, PIN_PID_PROBE))
    log("preflight: Phase 2 pins present: %s, %s, %s"
        % (PIN_STATS, PIN_KNOBS, PIN_DEMOTIONS))
    locate_bpftool()
    swept = sweep_stale_probes()
    if swept:
        log("preflight: swept %d stale probe file(s) from crashed "
            "previous runs" % swept)


def main():
    args = sys.argv[1:]
    test_mode = "--test" in args
    args = [a for a in args if a != "--test"]
    if "-h" in args or "--help" in args:
        print(USAGE)
        return 0
    if args:
        print("foresight_daemon: unknown argument(s): %s" % " ".join(args),
              file=sys.stderr, flush=True)
        print(USAGE, file=sys.stderr)
        return 6

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    preflight()

    # Effective rules: the mirrored C table, plus the two TEST-ONLY
    # comms when --test is given (never otherwise).
    rules = dict(CLASS_RULES)
    interactive = sorted(c for c, k in CLASS_RULES.items()
                         if k == CLASS_INTERACTIVE)
    batch = sorted(c for c, k in CLASS_RULES.items() if k == CLASS_BATCH)
    log("rules (mirror of class_rules in foresight_sched.c): "
        "interactive=%s batch=%s" % (",".join(interactive), ",".join(batch)))
    if test_mode:
        rules.update(TEST_RULES)
        log("--test: added TEST-ONLY rules: chrome->interactive, "
            "cargo->batch (not part of the C table)")

    # Map identity now: pre-proves bpftool works on the pins and gives
    # the restart detector its baseline. Reviewer SHOULD-FIX: this sat
    # OUTSIDE the exception ladder, so a DaemonError here escaped
    # main() as a raw traceback with an undocumented exit 1. It now
    # follows the documented ladder: pins gone -> clean exit 0 (pin
    # lifecycle contract); a real bpftool failure -> die(10) like any
    # other bpftool failure that stops the daemon.
    try:
        initial_ids = {}
        # Phase 2: the restart detector now watches all FIVE contract
        # pins - a restart replaces every map object, and the Phase 2
        # bookkeeping (EWMA baseline, knob belief, kernel_managed) must
        # be reset together with the classification state when it does.
        for pin in (PIN_TASK_CLASS, PIN_PID_PROBE,
                    PIN_STATS, PIN_KNOBS, PIN_DEMOTIONS):
            initial_ids[pin] = _show_map_id(pin, "preflight map id")
    except DaemonError as exc:
        if not pins_exist():
            log("scheduler pins vanished - the scheduler stopped; "
                "exiting cleanly")
            return 0
        die(10, "preflight map id", "%s" % exc)

    # Startup offset discovery. A SchedulerGone here means the scheduler
    # was stopped between preflight and now - same clean exit 0 as in
    # the loop, per the pin lifecycle contract.
    try:
        offset = discover_offset()
    except SchedulerGone:
        log("scheduler pins vanished - the scheduler stopped; exiting "
            "cleanly")
        return 0
    if offset is None:  # signal arrived during discovery
        log("signal received during startup; exiting before classification")
        return 0
    log("watching /proc every %.0fs; namespaced pid + %d = kernel-global "
        "pid used as task_class key" % (LOOP_INTERVAL_S, offset))

    children = []
    if test_mode:
        # Reviewer SHOULD-FIX: an OSError from the test children's
        # Popen (fork/exec failure) escaped the ladder as a raw
        # traceback with an undocumented exit 1; it is a documented
        # die(10) fatal now.
        try:
            children = spawn_test_children()
        except OSError as exc:
            die(10, "--test spawn",
                "could not spawn fake workloads (%s)" % exc)

    state = {}       # ns pid -> (global pid written, class); the
                     # recorded global pid is sticky for the task's
                     # life (reviewer BLOCKING fix - see header)
    failcount = {}   # ns pid -> consecutive update failures
    abandoned = set()  # ns pids we gave up updating this run
    fail_streak = 0  # consecutive wholly-failed loop passes
    pass_count = 0   # loop passes since start (drives offset rechecks)
    recheck_fails = 0

    # Phase 2 state in one object (so a detected scheduler restart can
    # reset it atomically): the adaptive-knob controller plus the
    # behavior-demotion listener's kernel_managed skip set. Both run
    # inside the loop's existing try block below and inherit its
    # exception ladder unchanged: SchedulerGone -> clean exit 0,
    # DaemonError -> fail_streak -> exit 10. No new exit codes.
    phase2 = Phase2State()

    try:
        while not exit_requested:
            # The pin check IS the scheduler-alive check (pin lifecycle
            # contract: pins vanish on every scheduler exit path).
            if not pins_exist():
                log("scheduler pins vanished - the scheduler stopped; "
                    "exiting cleanly")
                return 0
            pass_count += 1
            if pass_count % OFFSET_RECHECK_PASSES == 0:
                # Drift guard (see header). Reviewer BLOCKING fix: a
                # drift no longer deletes or re-keys tracked entries -
                # their recorded global pids were correct at write
                # time and stay correct until reap (a task's global
                # pid never changes, and cohort offsets only grow, so
                # ns_pid + new_offset would overshoot every pre-drift
                # task). The new offset is used ONLY for tasks first
                # seen from now on.
                recheck = refresh_offset()
                if recheck is None:
                    if exit_requested:
                        break  # signal mid-recheck: exit now, no retry noise
                    recheck_fails += 1
                    if recheck_fails >= RECHECK_GIVEUP:
                        die(4, "offset recheck",
                            "%d consecutive offset rechecks failed - is "
                            "pid_probe still healthy?" % RECHECK_GIVEUP)
                    log("offset recheck %d/%d failed; will retry next "
                        "cycle" % (recheck_fails, RECHECK_GIVEUP))
                else:
                    recheck_fails = 0
                    new_offset = recheck[0]
                    if new_offset != offset:
                        log("pid-namespace offset DRIFTED: +%d -> +%d "
                            "(WSL root-namespace infrastructure consumed "
                            "kernel-global pids); %d tracked entries keep "
                            "their recorded global pids; only NEW tasks "
                            "will be keyed with the new offset"
                            % (offset, new_offset, len(state)))
                        offset = new_offset
            try:
                # Maintainer fix (Phase 2 acceptance forensics): the five
                # `map show` calls in check_map_ids cost ~0.5-3.5s EACH
                # under CPU load (bpftool children compete in the batch
                # lane with the very hogs the kernel demoted there),
                # making every pass 10-30s. Gate the liveness sweep to
                # every 5th pass: restart detection gains a few passes
                # of latency; the pins check at loop top still catches
                # the common case instantly.
                if pass_count % MAP_ID_CHECK_PASSES == 0:
                    check_map_ids(initial_ids, state, failcount, abandoned,
                                  phase2)
                # Phase 2 listener BEFORE reconcile: events drained
                # this cycle must gate THIS cycle's classification
                # writes - otherwise a freshly-demoted pid is
                # re-classified interactive one full cycle before the
                # skip applies.
                drain_demotions(phase2)
                reconcile(rules, offset, state, failcount, abandoned,
                          phase2.kernel_managed)
                # Phase 2 adaptive-knob controller: stats -> rates ->
                # EWMA -> hysteresis -> at most one knobs RMW write.
                run_knob_cycle(phase2)
                poll_test_children(children)
                fail_streak = 0
            except SchedulerGone:
                log("scheduler pins vanished - the scheduler stopped; "
                    "exiting cleanly")
                return 0
            except DaemonError as exc:
                # Maintainer fix: fail fast when the scheduler died
                # mid-pass (observed live: rc=255 bpftool errors against
                # vanished pins, then up to 10 slow retries before the
                # give-up). The pins check is cheap; consult it first.
                if not pins_exist():
                    log("scheduler pins vanished - the scheduler stopped; "
                        "exiting cleanly")
                    return 0
                fail_streak += 1
                if fail_streak >= LOOP_FAIL_GIVEUP:
                    die(10, "classification loop",
                        "%d consecutive bpftool failures; last: %s"
                        % (LOOP_FAIL_GIVEUP, exc))
                log("loop pass failed (%d/%d): %s; will retry"
                    % (fail_streak, LOOP_FAIL_GIVEUP, exc))
            except Exception as exc:  # never crash on anything
                if not pins_exist():
                    log("scheduler pins vanished - the scheduler stopped; "
                        "exiting cleanly")
                    return 0
                fail_streak += 1
                if fail_streak >= LOOP_FAIL_GIVEUP:
                    die(10, "classification loop",
                        "%d consecutive failed passes; last: %r"
                        % (LOOP_FAIL_GIVEUP, exc))
                log("loop pass failed unexpectedly (%d/%d): %r; will retry"
                    % (fail_streak, LOOP_FAIL_GIVEUP, exc))
            nap(LOOP_INTERVAL_S)
    finally:
        # Kill test children on EVERY exit path (signal, pins-vanished,
        # fatal) - no orphaned busy-loopers, ever.
        kill_test_children(children)

    if exit_requested:
        log("%s received; shutting down cleanly"
            % (signal.Signals(last_signal).name if last_signal
               else "signal"))
        # Reviewer SHOULD-FIX: the signal exit path used to leave every
        # tracked entry in the map, so they accumulated across daemon
        # generations (live-observed stale pids persisting after clean
        # exits). Delete what this generation wrote before returning.
        # The pins-vanished exits above skip this: the map - and our
        # entries with it - are already gone.
        _drop_all_state(state, failcount, abandoned)
    return 0


if __name__ == "__main__":
    sys.exit(main())
