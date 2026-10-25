#!/usr/bin/env python3
"""foresight_phase2_tests.py - OFFLINE unit tests for the Phase 2
additions to foresight_daemon.py.

Pure stdlib, pure logic: no bpftool, no pins, no scheduler, no /proc.
The maintainer runs live acceptance separately; these tests pin down
exactly the pieces whose correctness does NOT depend on the live
system:

  1. The EWMA + hysteresis state machine (KnobController.observe):
     warmup gating, hot rule firing on the 3rd consecutive cycle (not
     the 2nd), cool recovery on the 5th (not the 4th), consecutiveness
     resets in the deadband, no double-writes while already at the
     target, adoption and reset semantics.
  2. The wire formats: struct.pack/unpack against the EXACT Phase 2
     contract layouts (little-endian), the knobs read-modify-write
     rebuild preserving every field the daemon does NOT own, and the
     bpftool-JSON parsers for stats/demotions entries (which reuse
     the daemon's existing parse_hex_field helper).

Output: a PASS/FAIL transcript, one line per case; exit 0 iff all
cases passed.
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import foresight_daemon as fsd


def approx(a, b, eps=1e-9):
    return abs(a - b) < eps


def feed(ctrl, rate):
    """One observation; returns the action (or None)."""
    return ctrl.observe(rate)


def warmup(ctrl, rate=40.0):
    """The KNOB_WARMUP_SAMPLES warmup observations (must never act)."""
    acts = [feed(ctrl, rate) for _ in range(fsd.KNOB_WARMUP_SAMPLES)]
    assert all(a is None for a in acts), "warmup produced an action"
    return acts


def _drive_hot(ctrl):
    """Drive a fresh controller from warmup through the hot firing and
    confirm the knob belief, so cool-recovery tests start hot."""
    warmup(ctrl, 40.0)
    act = None
    while act is None:
        act = feed(ctrl, 100.0)
    assert act[0] == "hot"
    ctrl.apply(act[1])
    return act


# ---------------------------------------------------------------------------
# 1. EWMA + hysteresis (synthetic rate sequences)
# ---------------------------------------------------------------------------

def test_ewma_seed_and_blend():
    c = fsd.KnobController()
    assert c.ewma is None
    assert feed(c, 100.0) is None
    assert approx(c.ewma, 100.0), "first observation must seed the EWMA"
    assert feed(c, 50.0) is None
    assert approx(c.ewma, 0.3 * 50.0 + 0.7 * 100.0), "alpha blend wrong"
    print("      ewma: seeded 100.0, then %.1f after one 50/s "
          "observation (expected 85.0)" % c.ewma)


def test_warmup_gates_every_rule():
    c = fsd.KnobController()
    # 1000/s from the very first observation: the EWMA is hugely hot,
    # yet the first KNOB_WARMUP_SAMPLES observations must stay silent
    # and the hot rule may only fire on the 3rd evaluated cycle after
    # warmup.
    n_silent = 0
    act = None
    for _ in range(fsd.KNOB_WARMUP_SAMPLES + 2):
        act = feed(c, 1000.0)
        if act is None:
            n_silent += 1
    assert act is None, "fired before 3 consecutive evaluated cycles"
    assert n_silent == fsd.KNOB_WARMUP_SAMPLES + 2
    act = feed(c, 1000.0)
    assert act is not None and act[0] == "hot", "must fire on cycle 3"
    assert act[2] == 3, "the rule reports its consecutive-cycle count"
    print("      warmup: %d silent observations despite ewma=1000; hot "
          "fired on evaluated cycle 3 (streak=%d)" % (n_silent, act[2]))


def test_hot_rule_three_consecutive_no_double_write():
    c = fsd.KnobController()
    warmup(c, 40.0)                      # ewma stays at 40 (deadband)
    assert feed(c, 100.0) is None and approx(c.ewma, 58.0)
    assert feed(c, 100.0) is None and approx(c.ewma, 70.6)
    act = feed(c, 100.0)
    assert act is not None, "3 consecutive >50/s cycles must fire"
    rule, target, streak, ewma = act
    assert rule == "hot" and target == fsd.INTERACTIVE_SLICE_FAST
    assert streak == 3, "firing must carry the 3-cycle count"
    assert ewma > fsd.KNOB_HOT_RATE
    c.apply(target)
    # Already at the target: sustained hot rates must NOT re-write
    # (no change -> no line -> no action).
    for _ in range(5):
        assert feed(c, 100.0) is None, "no double-write at the target"
    print("      hot: ewma 58.0 -> 70.6 -> %.2f; fired ONCE at streak "
          "3, silent afterwards" % ewma)


def test_hot_two_cycles_do_not_fire_and_streak_resets():
    c = fsd.KnobController()
    warmup(c, 40.0)
    assert feed(c, 100.0) is None
    assert feed(c, 100.0) is None, "2 consecutive cycles must NOT fire"
    # One deadband observation (ewma 49.42) breaks the run...
    assert feed(c, 0.0) is None and approx(c.ewma, 49.42)
    assert c.hot_streak == 0, "deadband must reset the streak"
    # ...so two more hot cycles still do not fire...
    assert feed(c, 100.0) is None
    assert feed(c, 100.0) is None, "a restarted run needs 3 again"
    # ...and only the third consecutive one does.
    act = feed(c, 100.0)
    assert act is not None and act[0] == "hot" and act[2] == 3
    print("      reset: 100,100 -> 0 (deadband) -> 100,100 all silent; "
          "the 3rd consecutive 100 fires")


def test_cool_rule_five_consecutive():
    c = fsd.KnobController()
    act = _drive_hot(c)                  # knob now at 10ms, ewma 79.42
    assert act[1] == fsd.INTERACTIVE_SLICE_FAST
    zeros = 0
    saw_four = 0
    act = None
    while act is None:
        act = feed(c, 0.0)
        zeros += 1
        if act is None and c.cool_streak >= 4:
            saw_four = c.cool_streak    # passed THROUGH 4 without firing
    assert act is not None and act[0] == "cool"
    assert act[1] == fsd.INTERACTIVE_SLICE_DEFAULT, "cool restores 20ms"
    assert act[2] == fsd.KNOB_COOL_STREAK == 5
    assert saw_four == 4, "cool must NOT fire at 4 consecutive cycles"
    # 2 above-50 + 2 deadband decay observations, then the 5 below-25:
    assert zeros == 8, "expected the fire on the 8th zero, got %d" % zeros
    c.apply(act[1])
    for _ in range(5):
        assert feed(c, 0.0) is None, "no double-write at the target"
    print("      cool: passed through streak 4 without firing; fired "
          "at streak 5 (the %d'th zero), silent afterwards" % zeros)


def test_deadband_is_silent():
    c = fsd.KnobController()
    warmup(c, 35.0)                      # ewma 35: inside [25, 50]
    for _ in range(30):
        assert feed(c, 35.0) is None
    assert c.hot_streak == 0 and c.cool_streak == 0
    print("      deadband: 40 observations at 35/s, no action, both "
          "streaks 0")


def test_adopt_and_reset_semantics():
    c = fsd.KnobController()
    c.adopt(fsd.INTERACTIVE_SLICE_FAST)
    assert c.slice_ns == fsd.INTERACTIVE_SLICE_FAST and c.synced
    # Knob already at 10ms: a hot EWMA must NOT fire a no-op "change"
    # (this is the previous-daemon-generation case).
    warmup(c, 100.0)
    for _ in range(5):
        assert feed(c, 100.0) is None, "must not re-write the target"
    c.reset()
    assert (c.ewma is None and c.samples == 0 and not c.synced
            and c.slice_ns == fsd.INTERACTIVE_SLICE_DEFAULT
            and c.hot_streak == 0 and c.cool_streak == 0)
    # After reset the warmup gate applies again: even 1000/s cannot
    # fire before warmup + 3 consecutive evaluated cycles.
    for _ in range(fsd.KNOB_WARMUP_SAMPLES + 2):
        assert feed(c, 1000.0) is None
    act = feed(c, 1000.0)
    assert act is not None and act[0] == "hot" and act[2] == 3
    print("      adopt+reset: adopted 10ms stays silent under a hot "
          "EWMA; reset restores warmup gating")


# ---------------------------------------------------------------------------
# 2. Wire formats (struct layout + read-modify-write encoding)
# ---------------------------------------------------------------------------

def test_knobs_struct_matches_contract():
    assert fsd.KNOBS_VALUE_FMT == "<QQII"
    assert fsd.KNOBS_VALUE_SIZE == struct.calcsize("<QQII") == 24
    packed = struct.pack(fsd.KNOBS_VALUE_FMT,
                         10_000_000, 20_000_000, 10, 0)
    assert len(packed) == 24
    # Field-by-field, little-endian, at the C struct's natural offsets:
    # u64 interactive_slice_ns @ 0
    assert packed[0:8] == (10_000_000).to_bytes(8, "little")
    assert packed[0:4] == b"\x80\x96\x98\x00"    # 10ms = 0x00989680
    # u64 batch_slice_ns @ 8
    assert packed[8:16] == (20_000_000).to_bytes(8, "little")
    assert packed[8:12] == b"\x00\x2d\x31\x01"   # 20ms = 0x01312d00
    # u32 demote_streak @ 16
    assert packed[16:20] == (10).to_bytes(4, "little")
    # u32 _pad @ 20
    assert packed[20:24] == b"\x00\x00\x00\x00"
    # Round trip through the daemon's own format string:
    assert struct.unpack(fsd.KNOBS_VALUE_FMT, packed) == \
        (10_000_000, 20_000_000, 10, 0)
    print("      knobs struct: 24 bytes LE; interactive@0 batch@8 "
          "streak@16 pad@20; the loader seed round-trips")


def test_knobs_rmw_preserves_unowned_fields():
    raw = struct.pack(fsd.KNOBS_VALUE_FMT, 20_000_000, 20_000_000, 10, 7)
    out = fsd.knobs_rebuild(raw, 10_000_000)
    assert out == struct.pack(fsd.KNOBS_VALUE_FMT, 10_000_000,
                              20_000_000, 10, 7)
    # The tail (batch_slice_ns, demote_streak, _pad) is byte-identical:
    assert out[8:] == raw[8:], "unowned fields must not change"
    assert out[0:8] == (10_000_000).to_bytes(8, "little")
    print("      knobs RMW: only interactive_slice_ns changes; batch/"
          "streak/pad bytes identical (pad=7 preserved)")


def test_demotion_struct_matches_contract():
    assert fsd.DEMOTION_VALUE_FMT == "<QBBH"
    assert fsd.DEMOTION_VALUE_MIN == struct.calcsize("<QBBH") == 12
    ts = 1729698000123456789
    body = struct.pack(fsd.DEMOTION_VALUE_FMT, ts, 1, 2, 10)
    assert len(body) == 12
    blob = body + b"\x00" * 4      # C struct is 8-aligned -> sizeof 16
    assert len(blob) == 16
    assert struct.unpack_from(fsd.DEMOTION_VALUE_FMT, blob, 0) == \
        (ts, 1, 2, 10), "must read the 12-byte body out of the 16-byte image"
    # Key: kernel-global pid, LE u32.
    key = (4242).to_bytes(4, "little")
    assert key == b"\x92\x10\x00\x00"
    assert int.from_bytes(key, "little") == 4242
    print("      demotion struct: 12-byte body in a 16-byte C image; "
          "key 4242 -> 92 10 00 00 (LE)")


# ---------------------------------------------------------------------------
# 3. bpftool-JSON entry parsers (reuse of the existing helpers)
# ---------------------------------------------------------------------------

def _hexlist(data):
    return ["0x%02x" % b for b in data]


def test_parse_stats_entries():
    entries = [
        {"key": _hexlist((0).to_bytes(4, "little")),
         "value": _hexlist((25).to_bytes(8, "little"))},
        {"key": _hexlist((1).to_bytes(4, "little")),
         "value": _hexlist((120).to_bytes(8, "little"))},
        {"key": _hexlist((2).to_bytes(4, "little")),
         "value": _hexlist((60).to_bytes(8, "little"))},
    ]
    got = fsd._parse_stats_entries(entries, "test")
    assert got == {0: 25, 1: 120, 2: 60}, got
    # Tolerated single-hex-string form (see parse_hex_field):
    got = fsd._parse_stats_entries(
        [{"key": _hexlist((1).to_bytes(4, "little")),
          "value": "7800000000000000"}], "test")
    assert got == {1: 120}
    # A PERCPU-shaped blob (value_size * nr_cpus, a multiple of 8) is
    # SUMMED like the C loader's read_stats does, not trusted as one
    # CPU's counter:
    blob = b"".join(v.to_bytes(8, "little") for v in (10, 20, 30, 40))
    got = fsd._parse_stats_entries(
        [{"key": _hexlist((1).to_bytes(4, "little")),
          "value": _hexlist(blob)}], "test")
    assert got == {1: 100}
    # Malformed junk is skipped, never fatal:
    bad = [
        {"key": ["0x01", "0x00", "0x00"],            # 3-byte key
         "value": _hexlist((9).to_bytes(8, "little"))},
        {"key": _hexlist((2).to_bytes(4, "little")),
         "value": ["0x01", "0x02", "0x03", "0x04", "0x05", "0x06"]},
        {"key": _hexlist((7).to_bytes(4, "little")),  # not a class key
         "value": _hexlist((9).to_bytes(8, "little"))},
    ]
    assert fsd._parse_stats_entries(bad, "test") == {}
    print("      stats parse: 3 class keys, string form tolerated, "
          "percpu blob summed (10+20+30+40=100), junk skipped")


def test_parse_demotion_entry():
    ts = 1729698000123456789
    blob = struct.pack(fsd.DEMOTION_VALUE_FMT, ts, 1, 2, 10) + b"\x00" * 4
    entry = {"key": _hexlist((4242).to_bytes(4, "little")),
             "value": _hexlist(blob)}
    got = fsd._parse_demotion_entry(entry)
    assert got == (4242, ts, 1, 2, 10, (4242).to_bytes(4, "little")), got
    # Contract violations are refused (None), never half-parsed:
    short = dict(entry, value=_hexlist(blob[:8]))
    assert fsd._parse_demotion_entry(short) is None
    badkey = dict(entry, key=_hexlist(b"\x92\x10\x00"))
    assert fsd._parse_demotion_entry(badkey) is None
    print("      demotion parse: pid 4242 ts=%d from=1 to=2 streak=10; "
          "short value / short key refused" % ts)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

TESTS = [
    ("ewma seed + alpha blend", test_ewma_seed_and_blend),
    ("warmup gates every rule", test_warmup_gates_every_rule),
    ("hot rule: 3 consecutive fires, 2 does not, no double write",
     test_hot_rule_three_consecutive_no_double_write),
    ("hot streak resets in the deadband",
     test_hot_two_cycles_do_not_fire_and_streak_resets),
    ("cool rule: 5 consecutive reverts, 4 does not",
     test_cool_rule_five_consecutive),
    ("deadband stays silent", test_deadband_is_silent),
    ("adopt + reset semantics", test_adopt_and_reset_semantics),
    ("knobs struct matches the contract",
     test_knobs_struct_matches_contract),
    ("knobs RMW preserves unowned fields",
     test_knobs_rmw_preserves_unowned_fields),
    ("demotion struct matches the contract",
     test_demotion_struct_matches_contract),
    ("stats entries parse (reused bpftool JSON helpers)",
     test_parse_stats_entries),
    ("demotion entries parse", test_parse_demotion_entry),
]


def main():
    print("foresight_phase2_tests: %d offline cases (stdlib only, no "
          "bpftool/scheduler needed)" % len(TESTS))
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print("PASS  %s" % name)
        except AssertionError as exc:
            failed += 1
            print("FAIL  %s: %s" % (name, exc))
        except Exception as exc:
            failed += 1
            print("ERROR %s: %r" % (name, exc))
    print("%d/%d passed" % (len(TESTS) - failed, len(TESTS)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
