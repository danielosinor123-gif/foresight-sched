#!/usr/bin/env python3
"""foresight_phase3_tests.py - OFFLINE unit tests for the Phase 3
(energy-adaptive scheduling) additions to foresight_daemon.py.

Pure stdlib, pure logic: no bpftool, no pins, no scheduler, no
PowerShell, no Windows. The maintainer runs live acceptance
separately; these tests pin down exactly the pieces whose correctness
does NOT depend on the live system:

  1. The energy state machine (EnergyState): startup state, immediate
     CONSERVE entry on a discharging sample, the 60s continuous-mains
     hysteresis on exit (59.9s must NOT exit, 60.0s must), plug jitter
     resetting the mains streak, unavailable/ambiguous samples treated
     as NO EVIDENCE (streak reset, never a flip), --force-conserve
     pinning CONSERVE against everything, adopt/apply/mark_restart
     belief semantics, and the state -> batch_slice_ns ownership map.
  2. The generalized knobs read-modify-write (knobs_rebuild): only the
     PROVIDED fields change; every other byte (including the other
     phase's slice, demote_streak and _pad) is preserved bit for bit;
     the Phase 2 positional call shape keeps working.
  3. The PowerShell JSON parser (_parse_power_ps_json) against the two
     EMPIRICALLY observed payload shapes (on-AC and discharging) plus
     array shapes and degraded/ambiguous inputs.
  4. The energy accounting math (_compute_cpu_rates,
     _select_batch_lane): correct tick scaling, vanished-pid skip,
     pid-reuse baseline reset via starttime, negative-delta skip, and
     the batch-lane selection (daemon-classified batch pids +
     unclassified >50%-core hogs; rules-matching non-batch comms
     excluded).
  5. The --energy-probe line contract (_energy_probe_dict): fixed key
     order == ENERGY_PROBE_KEYS, JSON round trip, null for unknowns.
  6. clk_tck() sanity and the /proc stat sampler's shape contract.

Output: a PASS/FAIL transcript, one line per case; exit 0 iff all
cases passed.
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import foresight_daemon as fsd


# ---------------------------------------------------------------------------
# 1. Energy state machine (transitions + hysteresis)
# ---------------------------------------------------------------------------

SAMPLE_BATTERY = {"present": True, "source": "powershell",
                  "on_battery": True, "percent": 47.0,
                  "drain_mw": 21790.0, "cross_check": "agree",
                  "win32_battery_status": 1, "power_online": False}
SAMPLE_MAINS = {"present": True, "source": "powershell",
                "on_battery": False, "percent": 47.0,
                "drain_mw": 0.0, "cross_check": "agree",
                "win32_battery_status": 2, "power_online": True}
SAMPLE_ABSENT = dict(fsd.ENERGY_SAMPLE_ABSENT)
SAMPLE_AMBIGUOUS = {"present": True, "source": "powershell",
                    "on_battery": None, "percent": None,
                    "drain_mw": None, "cross_check": "unknown",
                    "win32_battery_status": None, "power_online": None}


def observe_at(state, sample, now):
    """Set the cached sample and feed the machine at monotonic now."""
    state.sample = sample
    return state.observe(now)


def test_startup_state_and_no_evidence_is_noop():
    e = fsd.EnergyState()
    assert e.state == fsd.ENERGY_STATE_PERFORMANCE
    # Default (absent) sample: NO evidence, no transition, ever.
    for t in (0.0, 10.0, 100.0, 1000.0):
        assert observe_at(e, dict(SAMPLE_ABSENT), t) is None
    assert e.state == fsd.ENERGY_STATE_PERFORMANCE
    assert e.desired_batch_slice_ns() == fsd.BATCH_SLICE_DEFAULT
    print("      startup: PERFORMANCE; absent samples are no-ops "
          "forever (absence is not evidence)")


def test_conserve_entry_is_immediate():
    e = fsd.EnergyState()
    act = observe_at(e, dict(SAMPLE_BATTERY), 100.0)
    assert act is not None and act[0] == "enter_conserve"
    assert e.state == fsd.ENERGY_STATE_CONSERVE
    assert "47.0" in act[1] and "21790" in act[1], \
        "the trigger text carries battery percent and drain mW"
    assert e.desired_batch_slice_ns() == fsd.BATCH_SLICE_CONSERVE
    # Already CONSERVE: a repeated battery observation stays silent.
    assert observe_at(e, dict(SAMPLE_BATTERY), 110.0) is None
    print("      entry: first discharging sample enters CONSERVE "
          "immediately (percent=47.0, drain=21790 in the trigger); "
          "repeat observations stay silent")


def test_hysteresis_exit_boundary():
    e = fsd.EnergyState()
    observe_at(e, dict(SAMPLE_BATTERY), 0.0)      # -> CONSERVE
    act = observe_at(e, dict(SAMPLE_MAINS), 10.0)  # arms the clock
    assert act is None and e.mains_since == 10.0
    # 59.9s of continuous mains: still CONSERVE (must NOT exit).
    assert observe_at(e, dict(SAMPLE_MAINS), 10.0 + 59.9) is None
    assert e.state == fsd.ENERGY_STATE_CONSERVE
    # The 60th second: exit.
    act = observe_at(e, dict(SAMPLE_MAINS), 10.0 + 60.0)
    assert act is not None and act[0] == "exit_conserve"
    assert e.state == fsd.ENERGY_STATE_PERFORMANCE
    assert e.desired_batch_slice_ns() == fsd.BATCH_SLICE_DEFAULT
    assert "60" in act[1], "the trigger text names the held duration"
    print("      hysteresis: 59.9s of mains does NOT exit; 60.0s does "
          "(clock armed at the first mains reading)")


def test_plug_jitter_resets_the_mains_streak():
    e = fsd.EnergyState()
    observe_at(e, dict(SAMPLE_BATTERY), 0.0)       # -> CONSERVE
    assert observe_at(e, dict(SAMPLE_MAINS), 10.0) is None   # armed
    # One battery blip (plug jitter) at t=40: the streak must die.
    assert observe_at(e, dict(SAMPLE_BATTERY), 40.0) is None
    assert e.mains_since is None
    # Mains again at t=41: a FRESH 60s window must elapse.
    assert observe_at(e, dict(SAMPLE_MAINS), 41.0) is None
    assert observe_at(e, dict(SAMPLE_MAINS), 41.0 + 59.0) is None, \
        "59s after the blip must NOT exit (jitter reset the clock)"
    act = observe_at(e, dict(SAMPLE_MAINS), 41.0 + 60.0)
    assert act is not None and act[0] == "exit_conserve"
    print("      jitter: battery blip at t=40 kills the streak; exit "
          "comes only 60s after the LAST continuous-mains start")


def test_unavailable_and_ambiguous_samples_break_the_streak_only():
    e = fsd.EnergyState()
    observe_at(e, dict(SAMPLE_BATTERY), 0.0)       # -> CONSERVE
    assert observe_at(e, dict(SAMPLE_MAINS), 10.0) is None   # armed
    # A collector failure (present=False) is NOT mains: the streak
    # resets and the state stays CONSERVE (fail-safe direction).
    assert observe_at(e, dict(SAMPLE_ABSENT), 70.0) is None
    assert e.state == fsd.ENERGY_STATE_CONSERVE and e.mains_since is None
    # Ambiguous (present but on_battery None) behaves the same.
    assert observe_at(e, dict(SAMPLE_MAINS), 71.0) is None    # re-armed
    assert observe_at(e, dict(SAMPLE_AMBIGUOUS), 100.0) is None
    assert e.state == fsd.ENERGY_STATE_CONSERVE and e.mains_since is None
    # ...and from PERFORMANCE, neither sample ever flips the state.
    act = observe_at(e, dict(SAMPLE_MAINS), 101.0)            # re-arm
    act = observe_at(e, dict(SAMPLE_MAINS), 101.0 + 60.0)     # exit
    assert act is not None and act[0] == "exit_conserve"
    assert observe_at(e, dict(SAMPLE_AMBIGUOUS), 200.0) is None
    assert observe_at(e, dict(SAMPLE_ABSENT), 210.0) is None
    assert e.state == fsd.ENERGY_STATE_PERFORMANCE
    print("      absence/ambiguity: reset the mains streak, never flip "
          "the state; staying in CONSERVE is the fail-safe direction")


def test_force_conserve_pins_the_state():
    e = fsd.EnergyState(force_conserve=True)
    assert e.state == fsd.ENERGY_STATE_CONSERVE, \
        "forced mode starts in CONSERVE (the acceptance runs on AC)"
    assert e.desired_batch_slice_ns() == fsd.BATCH_SLICE_CONSERVE
    # Mains, battery, absent, ambiguous: nothing may un-pin it.
    for sample, t in ((dict(SAMPLE_MAINS), 10.0), (dict(SAMPLE_BATTERY), 20.0),
                      (dict(SAMPLE_MAINS), 100.0), (dict(SAMPLE_MAINS), 1000.0),
                      (dict(SAMPLE_ABSENT), 1010.0),
                      (dict(SAMPLE_AMBIGUOUS), 1020.0)):
        assert observe_at(e, sample, t) is None
        assert e.state == fsd.ENERGY_STATE_CONSERVE
    print("      --force-conserve: CONSERVE from construction; mains "
          "for 990s+ cannot exit it")


def test_adopt_apply_mark_restart_semantics():
    e = fsd.EnergyState()
    assert not e.synced and e.batch_slice_ns == fsd.BATCH_SLICE_DEFAULT
    e.adopt(fsd.BATCH_SLICE_CONSERVE)
    assert e.synced and e.batch_slice_ns == fsd.BATCH_SLICE_CONSERVE
    e.apply(fsd.BATCH_SLICE_DEFAULT)
    assert e.batch_slice_ns == fsd.BATCH_SLICE_DEFAULT
    e.mark_restart()
    assert not e.synced, "restart drops the sync so the map is re-adopted"
    # State machine internals (hysteresis clock, power state) survive:
    # power is machine-level, not scheduler-level.
    observe_at(e, dict(SAMPLE_BATTERY), 0.0)
    e.mark_restart()
    assert e.state == fsd.ENERGY_STATE_CONSERVE
    print("      adopt/apply/restart: restart drops ONLY the knob "
          "belief; the energy state itself survives")


# ---------------------------------------------------------------------------
# 2. Generalized knobs read-modify-write (both owners, one encoding)
# ---------------------------------------------------------------------------

def test_knobs_rmw_generalized_preserves_everything_else():
    raw = struct.pack(fsd.KNOBS_VALUE_FMT, 20_000_000, 20_000_000, 10, 7)
    # Phase 2 shape (positional interactive only) keeps working...
    out = fsd.knobs_rebuild(raw, 10_000_000)
    assert out == struct.pack(fsd.KNOBS_VALUE_FMT, 10_000_000,
                              20_000_000, 10, 7)
    assert out[8:] == raw[8:], "unowned tail must be byte-identical"
    # ...PHASE 3: batch only (keyword)...
    out = fsd.knobs_rebuild(raw, batch_ns=5_000_000)
    assert out == struct.pack(fsd.KNOBS_VALUE_FMT, 20_000_000,
                              5_000_000, 10, 7)
    assert out[0:8] == raw[0:8], "Phase 2's interactive field untouched"
    # ...both fields at once...
    out = fsd.knobs_rebuild(raw, interactive_ns=10_000_000,
                            batch_ns=5_000_000)
    assert out == struct.pack(fsd.KNOBS_VALUE_FMT, 10_000_000,
                              5_000_000, 10, 7)
    # ...and neither: a pure identity copy.
    assert fsd.knobs_rebuild(raw) == raw
    # demote_streak and _pad survive in EVERY case (never zeroed).
    for out in (fsd.knobs_rebuild(raw, 1),
                fsd.knobs_rebuild(raw, batch_ns=1),
                fsd.knobs_rebuild(raw, 1, 1), fsd.knobs_rebuild(raw)):
        assert out[16:] == raw[16:], "streak/pad must never change"
    print("      knobs RMW: None = keep; Phase 2 positional shape "
          "intact; batch-only/both/identity all preserve streak=10, "
          "pad=7 bit for bit")


# ---------------------------------------------------------------------------
# 3. PowerShell JSON parser (the two empirically observed shapes + junk)
# ---------------------------------------------------------------------------

PS_ON_AC = ('{"status":{"Charging":true,"Discharging":false,'
            '"PowerOnline":true,"DischargeRate":0,"ChargeRate":27632},'
            '"battery":{"EstimatedChargeRemaining":66,"BatteryStatus":2}}')
PS_DISCHARGING = ('{"status":{"Charging":false,"Discharging":true,'
                  '"PowerOnline":false,"DischargeRate":22839,'
                  '"ChargeRate":0},"battery":{"EstimatedChargeRemaining":47,'
                  '"BatteryStatus":1}}')


def test_ps_json_on_ac_shape():
    s = fsd._parse_power_ps_json(PS_ON_AC)
    assert s["present"] is True and s["source"] == "powershell"
    assert s["on_battery"] is False and s["percent"] == 66.0
    assert s["drain_mw"] == 0.0, "on AC the measured drain is 0"
    assert s["cross_check"] == "agree", \
        "root/wmi Discharging=false vs Win32 BatteryStatus=2 (AC)"
    print("      PS on-AC (observed live): Discharging=false, "
          "BatteryStatus=2, percent=66, drain=0, sources agree")


def test_ps_json_discharging_shape():
    s = fsd._parse_power_ps_json(PS_DISCHARGING)
    assert s["present"] is True and s["on_battery"] is True
    assert s["percent"] == 47.0 and s["drain_mw"] == 22839.0
    assert s["cross_check"] == "agree", \
        "root/wmi Discharging=true vs Win32 BatteryStatus=1"
    print("      PS discharging (observed live): Discharging=true, "
          "BatteryStatus=1, percent=47, drain=22839 mW")


def test_ps_json_array_shapes_and_degraded_inputs():
    # Multi-instance hosts: ConvertTo-Json emits ARRAYS; the first
    # mapping at every level must be taken.
    arr = ('{"status":[{"Discharging":true,"DischargeRate":20000},'
           '{"Discharging":false,"DischargeRate":0}],'
           '"battery":[{"EstimatedChargeRemaining":50,"BatteryStatus":1}]}')
    s = fsd._parse_power_ps_json(arr)
    assert s["on_battery"] is True and s["drain_mw"] == 20000.0
    assert s["percent"] == 50.0 and s["cross_check"] == "agree"
    # ChargeRate is inflow: never reported as drain, even when present.
    s = fsd._parse_power_ps_json(PS_ON_AC)
    assert s["drain_mw"] != 27632
    # One source silent: cross_check says so; the primary still decides.
    half = ('{"status":{"Discharging":false,"DischargeRate":0},'
            '"battery":{}}')
    s = fsd._parse_power_ps_json(half)
    assert s["on_battery"] is False and s["cross_check"] == "single-source"
    # Sources disagree: flagged, root/wmi wins (the verified primary).
    conflict = ('{"status":{"Discharging":false,"DischargeRate":0},'
                '"battery":{"EstimatedChargeRemaining":50,'
                '"BatteryStatus":1}}')
    s = fsd._parse_power_ps_json(conflict)
    assert s["cross_check"] == "disagree" and s["on_battery"] is False
    # No usable signal at all: NO EVIDENCE, never a guess.
    s = fsd._parse_power_ps_json('{"status":{},"battery":{}}')
    assert s["on_battery"] is None and s["drain_mw"] is None
    assert s["cross_check"] == "unknown" and s["present"] is True
    # Unparseable junk raises ValueError (the collector degrades).
    for junk in ("", "not json", "[]", "3"):
        try:
            fsd._parse_power_ps_json(junk)
        except ValueError:
            pass
        else:
            raise AssertionError("junk %r must raise ValueError" % junk)
    print("      PS arrays/edges: array shapes taken field-by-field, "
          "ChargeRate never counted as drain, single-source/disagree/"
          "unknown flagged, junk raises ValueError")


def test_first_cim_mapping():
    assert fsd._first_cim_mapping({"a": 1}) == {"a": 1}
    assert fsd._first_cim_mapping([{"a": 1}, {"b": 2}]) == {"a": 1}
    assert fsd._first_cim_mapping([1, {"a": 2}]) == {"a": 2}
    assert fsd._first_cim_mapping([]) == {}
    assert fsd._first_cim_mapping(None) == {}
    assert fsd._first_cim_mapping("junk") == {}
    print("      _first_cim_mapping: dict passes through, arrays "
          "yield the first mapping, junk yields {}")


# ---------------------------------------------------------------------------
# 4. Energy accounting math
# ---------------------------------------------------------------------------

def test_compute_cpu_rates_scaling_and_reuse():
    old = fsd._CLK_TCK
    fsd._CLK_TCK = 100  # deterministic scale for the test
    try:
        prev = {1: (5000, "cargo", 100), 2: (700, "make", 1000),
                3: (9, "bash", 50)}
        cur = {1: (5000, "cargo", 250),   # +150 ticks in 30s -> 3.0 s/min
               2: (700, "make", 900),     # negative delta: skipped
               3: (12, "bash", 9999),     # REUSED pid (starttime): reset
               4: (77, "cargo", 1000)}    # brand-new pid: no rate yet
        rates = fsd._compute_cpu_rates(prev, cur, 0.5)  # 30s window
        assert rates == {1: ("cargo", 3.0)}, rates
        # A full 60s window at one core: 6000 ticks -> 60 s/min.
        rates = fsd._compute_cpu_rates({1: (5, "x", 0)},
                                       {1: (5, "x", 6000)}, 1.0)
        assert abs(rates[1][1] - 60.0) < 1e-9
    finally:
        fsd._CLK_TCK = old
    print("      rates: 150 ticks/100Hz/0.5min = 3.0 s/min; vanished "
          "pids skipped; reused pid (starttime 9->12) baseline-reset; "
          "negative delta skipped; 6000 ticks/min = one full core")


def test_select_batch_lane():
    rules = dict(fsd.CLASS_RULES)  # make->batch, bash->interactive, ...
    rates = {1: ("cargo", 50.0),    # unclassified, >30 -> batch-lane hog
             2: ("make", 40.0),     # daemon-classified batch -> counted
             3: ("bash", 55.0),     # rules-matched (interactive) -> NO
             4: ("python3", 10.0),  # unclassified but <30% core -> NO
             5: ("cargo", 20.0),    # unclassified, 33% core -> NO
             6: ("vim", 45.0)}      # rules-matched (interactive) -> NO
    total, n_cls, n_hogs = fsd._select_batch_lane(rates, rules, {2})
    assert abs(total - 90.0) < 1e-9 and n_cls == 1 and n_hogs == 1, \
        (total, n_cls, n_hogs)
    # The strict boundary: exactly 30.0 s/min (50% of a core) is NOT a
    # hog (">50%" is strict, like the Phase 2 comparisons).
    total, _, n_hogs = fsd._select_batch_lane(
        {9: ("cargo", 30.0)}, rules, set())
    assert total == 0.0 and n_hogs == 0
    total, _, _ = fsd._select_batch_lane(
        {9: ("cargo", 30.0001)}, rules, set())
    assert total > 30.0
    print("      batch lane: daemon-batch pids + unclassified >30 "
          "s/min hogs counted; rules-matched interactive comms and "
          "quiet tasks excluded; 30.0 exactly is NOT a hog")


def test_energy_probe_dict_contract():
    body = fsd._energy_probe_dict("conserve", 47.0, 21790.0, 120.31,
                                  20_000_000, 5_000_000)
    assert tuple(body) == fsd.ENERGY_PROBE_KEYS, \
        "the key order IS the wire contract"
    line = json.dumps(body, separators=(",", ":"))
    back = json.loads(line)
    assert tuple(back) == fsd.ENERGY_PROBE_KEYS
    assert back["mode"] == "conserve" and back["batch_slice_ns"] == 5000000
    # Unknown values ride along as nulls (keys always present).
    body = fsd._energy_probe_dict("performance", None, None, None,
                                  1, 2)
    assert list(json.loads(json.dumps(body)).values()) == \
        ["performance", None, None, None, 1, 2]
    print("      probe line: fixed key order == ENERGY_PROBE_KEYS, "
          "JSON round-trips, nulls for unknowns, 5ms visible in "
          "batch_slice_ns")


# ---------------------------------------------------------------------------
# 5. Environment-independent sanity (clk scale + /proc stat shape)
# ---------------------------------------------------------------------------

def test_clk_tck_sane_and_cached():
    first = fsd.clk_tck()
    assert isinstance(first, int) and first > 0
    assert fsd.clk_tck() == first, "must be cached"
    print("      clk_tck: %d (cached, positive int)" % first)


def test_read_proc_stat_sample_shape():
    sample = fsd._read_proc_stat_sample()
    assert isinstance(sample, dict)
    for pid, (start, comm, ticks) in sample.items():
        assert isinstance(pid, int) and pid > 0
        assert isinstance(start, int) and start >= 0
        assert isinstance(comm, str) and len(comm) <= 15
        assert isinstance(ticks, int) and ticks >= 0
    print("      /proc stat sample: %d tasks, all values "
          "(int starttime, str comm<=15, int ticks>=0)" % len(sample))


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

TESTS = [
    ("startup state + absent samples are no-ops",
     test_startup_state_and_no_evidence_is_noop),
    ("CONSERVE entry is immediate, trigger carries percent+drain",
     test_conserve_entry_is_immediate),
    ("hysteresis: 59.9s no, 60.0s yes", test_hysteresis_exit_boundary),
    ("plug jitter resets the mains streak",
     test_plug_jitter_resets_the_mains_streak),
    ("unavailable/ambiguous samples break the streak only",
     test_unavailable_and_ambiguous_samples_break_the_streak_only),
    ("--force-conserve pins the state", test_force_conserve_pins_the_state),
    ("adopt/apply/mark_restart semantics",
     test_adopt_apply_mark_restart_semantics),
    ("knobs RMW generalized preserves everything else",
     test_knobs_rmw_generalized_preserves_everything_else),
    ("PS JSON: on-AC shape (observed live)", test_ps_json_on_ac_shape),
    ("PS JSON: discharging shape (observed live)",
     test_ps_json_discharging_shape),
    ("PS JSON: array shapes + degraded inputs",
     test_ps_json_array_shapes_and_degraded_inputs),
    ("_first_cim_mapping", test_first_cim_mapping),
    ("cpu rates: scaling, reuse reset, vanished, negative",
     test_compute_cpu_rates_scaling_and_reuse),
    ("batch-lane selection rules", test_select_batch_lane),
    ("energy-probe line contract", test_energy_probe_dict_contract),
    ("clk_tck sane + cached", test_clk_tck_sane_and_cached),
    ("/proc stat sampler shape", test_read_proc_stat_sample_shape),
]


def main():
    print("foresight_phase3_tests: %d offline cases (stdlib only, no "
          "bpftool/scheduler/PowerShell needed)" % len(TESTS))
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
