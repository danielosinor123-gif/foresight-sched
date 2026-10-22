#!/usr/bin/env python3
"""
foresight_daemon.py - Phase 1 LIVE classification daemon for the
foresight_sched sched_ext scheduler (stdlib-only Python 3).

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
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Contract constants (must match foresight_sched.c / foresight_sched.bpf.c)
# ---------------------------------------------------------------------------

PIN_DIR = "/sys/fs/bpf/foresight"
PIN_TASK_CLASS = PIN_DIR + "/task_class"  # BPF hash: u32 global pid -> u8 class
PIN_PID_PROBE = PIN_DIR + "/pid_probe"    # BPF hash: char[16] comm -> u32 global pid

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
RECHECK_GIVEUP = 5             # consecutive failed rechecks before dying

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


def reconcile(rules, offset, state, failcount, abandoned):
    """Bring task_class in line with what /proc says, printing changes only.

    state:      {namespaced pid -> (global pid written, class)} - the
                global pid is RECORDED at classification time and is
                sticky for the task's whole life (reviewer BLOCKING
                fix: a task's global pid never changes, so the
                recorded key stays correct even after the live offset
                drifts; see header)
    failcount:  {namespaced pid -> consecutive update failures}
    abandoned:  {namespaced pid} we gave up updating this run
    """
    comms = scan_proc_comms()
    desired = {}
    for ns_pid, comm in comms.items():
        cls = rules.get(comm)
        if cls is not None:
            desired[ns_pid] = (cls, comm)

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


def check_map_ids(initial_ids, state, failcount, abandoned):
    """Detect a scheduler restart that was too fast for the pins check.

    A fresh scheduler instance pins NEW map objects; bpftool's map id
    changes. On change, best-effort-delete our tracked keys from the
    CURRENT map and clear bookkeeping (reviewer NOTE): the fresh map
    is normally empty, so most deletes hit ENOENT - harmless - but a
    key that does exist was written against this very map and would
    otherwise be orphaned with no owner left to reap it. Every
    classification is then re-written from scratch.
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
    for pin in (PIN_TASK_CLASS, PIN_PID_PROBE):
        if not os.path.exists(pin):
            die(2, "preflight",
                "pin %s does not exist - is the scheduler running? "
                "(also: WSL2 gives each wsl session its own mount "
                "namespace; run this daemon where the scheduler was "
                "started, e.g. via "
                "'nsenter -t $(pgrep -x foresight_sched) -m -- python3 "
                "foresight_daemon.py')" % pin)
    log("preflight: pins present: %s, %s" % (PIN_TASK_CLASS, PIN_PID_PROBE))
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
        for pin in (PIN_TASK_CLASS, PIN_PID_PROBE):
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
                check_map_ids(initial_ids, state, failcount, abandoned)
                reconcile(rules, offset, state, failcount, abandoned)
                poll_test_children(children)
                fail_streak = 0
            except SchedulerGone:
                log("scheduler pins vanished - the scheduler stopped; "
                    "exiting cleanly")
                return 0
            except DaemonError as exc:
                fail_streak += 1
                if fail_streak >= LOOP_FAIL_GIVEUP:
                    die(10, "classification loop",
                        "%d consecutive bpftool failures; last: %s"
                        % (LOOP_FAIL_GIVEUP, exc))
                log("loop pass failed (%d/%d): %s; will retry"
                    % (fail_streak, LOOP_FAIL_GIVEUP, exc))
            except Exception as exc:  # never crash on anything
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
