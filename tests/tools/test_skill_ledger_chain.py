"""Pure-policy acceptance set for the `chain_break` annotation contract (card `t_5c89799a`).

Verbatim port of `chain_break_policy_controls_1.py` (card `t_7cc3bc69`, revision 5, sha256
`aa67fcb2c580bb…`): every cell of the total outcome table gets a case, plus the documented
residuals, the artefact rule, the authenticated-empty-map rule (R5 item 2, controls 14a-14d)
and the provenance-resolution rule (R5 item 3, controls 13a-13f).

These are **pure-policy** controls: they call the policy functions with facts. They do NOT
stand in for the real multi-process acceptance test, which lives in
`tests/tools/test_skill_ledger.py::test_chain_break_two_process_interleave_is_unverified` and
cannot be proved by a single-process control. Control 12's label says exactly what it
demonstrates: the outcome the policy produces when its freshness read missed a later append —
the documented non-coverage, not a guarantee.

Expected executed assertion count: 29 (`test_controls_execute_all_29_assertions`).
"""

import pytest

from tools import skill_ledger_chain as P

X = "a" * 64
Y = "b" * 64
PKG = "/home/david-wu/.hermes/skills/personal-infra/beta/SKILL.md"
PYC = "/home/david-wu/.hermes/skills/personal-infra/beta/scripts/__pycache__/x.pyc"


def _out(before, last, recorded: str | None = "e9", tail: str | None = "e9",
         tail_readable=True):
    return P.chain_break_outcome(before_map=before, last_after_map=last,
                                 recorded_id=recorded, tail_id=tail, tail_readable=tail_readable)


def _run_controls():
    """Run every control, returning (executed, failures). Labels kept verbatim."""
    executed = 0
    failures = []

    def check(label, cond, detail=""):
        nonlocal executed
        executed += 1
        if not cond:
            failures.append(label + " " + detail)

    # --- total outcome table -------------------------------------------------

    # present + fresh + equal -> false
    r = _out({PKG: X}, {PKG: X})
    check("1 present/fresh/equal -> chain_break false",
          r["chain_break"] is False and r["chain_break_basis"] == P.BASIS_FRESHNESS
          and r["chain_break_paths"] == [], str(r))

    # present + fresh + differ -> true + paths
    r = _out({PKG: Y}, {PKG: X})
    check("2 present/fresh/differ -> chain_break true + paths",
          r["chain_break"] is True and r["chain_break_basis"] == P.BASIS_FRESHNESS
          and r["chain_break_paths"] == [PKG], str(r))

    # present + stale + equal -> "unverified"  (rev 3's contradiction, resolved this way)
    r = _out({PKG: X}, {PKG: X}, tail="e10")
    check('3 present/stale/equal -> "unverified" (stale-sidecar), never false',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_STALE_SIDECAR
          and r["chain_break_paths"] == [], str(r))

    # present + stale + differ -> "unverified" + paths
    r = _out({PKG: Y}, {PKG: X}, tail="e10")
    check('4 present/stale/differ -> "unverified" + paths',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_STALE_SIDECAR
          and r["chain_break_paths"] == [PKG], str(r))

    # missing sidecar record / no last-known map -> "unverified" (no comparison)
    r = _out({PKG: X}, None)
    check('5 no last-known map (cold process) -> "unverified" (no-sidecar)',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_NO_SIDECAR
          and r["chain_break_paths"] == [], str(r))

    # unreadable ledger tail -> "unverified", paths reported when a difference exists
    r = _out({PKG: Y}, {PKG: X}, tail=None, tail_readable=False)
    check('6 unreadable tail + differ -> "unverified" (no-sidecar) + paths',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_NO_SIDECAR
          and r["chain_break_paths"] == [PKG], str(r))
    r = _out({PKG: X}, {PKG: X}, tail=None, tail_readable=False)
    check('6b unreadable tail + equal -> "unverified", not false',
          r["chain_break"] == "unverified", str(r))

    # recorded_id missing but a map present -> not a comparison basis
    r = P.chain_break_outcome(before_map={PKG: X}, last_after_map={PKG: X}, recorded_id=None,
                              tail_id="e9")
    check('7 last-known map with no recorded ledger id -> "unverified"',
          r["chain_break"] == "unverified", str(r))

    # --- artefact rule and residuals -----------------------------------------

    # artefact-only difference on a fresh tail -> false
    r = _out({PKG: X, PYC: "c" * 64}, {PKG: X})
    check("8 __pycache__ churn only, fresh -> chain_break false",
          r["chain_break"] is False and r["chain_break_paths"] == [], str(r))

    # artefact churn must not mask a real change
    r = _out({PKG: Y, PYC: "c" * 64}, {PKG: X})
    check("9 artefact churn alongside a real change -> true, artefact excluded from paths",
          r["chain_break"] is True and r["chain_break_paths"] == [PKG], str(r))

    # the key is always present, with one of exactly three states
    states = set()
    for before, last, rec, tail, tr in (
            ({PKG: X}, {PKG: X}, "e9", "e9", True),
            ({PKG: Y}, {PKG: X}, "e9", "e9", True),
            ({PKG: X}, {PKG: X}, "e9", "e10", True),
            ({PKG: Y}, {PKG: X}, "e9", "e10", True),
            ({PKG: X}, None, "e9", "e9", True),
            ({PKG: Y}, {PKG: X}, "e9", None, False)):
        r = _out(before, last, rec, tail, tr)
        check("10 key always present with a legal value (%s)" % (r["chain_break"],),
              set(r) == {"chain_break", "chain_break_basis", "chain_break_paths"}
              and r["chain_break"] in (True, False, "unverified")
              and r["chain_break_basis"] in (P.BASIS_FRESHNESS, P.BASIS_STALE_SIDECAR,
                                             P.BASIS_NO_SIDECAR), str(r))
        states.add(r["chain_break"])
    check("11 all three states reachable", states == {True, False, "unverified"}, str(states))

    # Documented non-coverage: the policy is *given* the tail its own freshness read observed.
    # When a second process appends AFTER that read, the policy still compares against the basis
    # it recorded -> a real difference yields `true`. That is the residual being unobservable
    # here, not a guarantee that no append happened.
    r = P.chain_break_outcome(before_map={PKG: Y}, last_after_map={PKG: X}, recorded_id="e9",
                              tail_id="e9")
    check("12 post-freshness-read append (residual): the observed tail is passed and a difference "
          "still yields true - documented non-coverage, not a guarantee",
          r["chain_break"] is True and r["chain_break_paths"] == [PKG], str(r))
    check("12b the residual is a *missing observation*, not a `true`-suppressing cell: a tail the "
          'policy did observe as different still yields "unverified", never true',
          P.chain_break_outcome(before_map={PKG: Y}, last_after_map={PKG: X}, recorded_id="e9",
                                tail_id="e11")["chain_break"] == "unverified", "")

    # --- 13 provenance resolution (R5 item 3) --------------------------------

    # warm in-memory record + sidecar deleted -> the record is the basis; NOT unverified
    mm, mid = P.resolve_basis(memory_map={PKG: X}, memory_id="e9", sidecar_map=None,
                              sidecar_id="e9", sidecar_readable=False)
    check("13a warm in-memory record survives a deleted sidecar",
          mm == {PKG: X} and mid == "e9", "%s %s" % (mm, mid))
    r = _out({PKG: X}, mm, mid, "e9")
    check("13b warm record + deleted sidecar + fresh tail + equal -> false (not unverified)",
          r["chain_break"] is False, str(r))
    r = _out({PKG: Y}, mm, mid, "e9")
    check("13c warm record + deleted sidecar + fresh tail + differ -> true",
          r["chain_break"] is True, str(r))

    # cold process + readable sidecar -> the sidecar is the basis
    mm, mid = P.resolve_basis(memory_map=None, memory_id=None, sidecar_map={PKG: X},
                              sidecar_id="e9", sidecar_readable=True)
    check("13d cold process reads the sidecar", mm == {PKG: X} and mid == "e9", "%s %s" % (mm, mid))

    # cold process + deleted/unreadable sidecar -> genuinely no basis
    mm, mid = P.resolve_basis(memory_map=None, memory_id=None, sidecar_map={PKG: X},
                              sidecar_id="e9", sidecar_readable=False)
    check("13e cold process + unreadable sidecar -> no basis", mm is None and mid is None,
          "%s %s" % (mm, mid))
    r = _out({PKG: X}, mm, mid)
    check('13f ... and the outcome is "unverified"/no-sidecar, no exception',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_NO_SIDECAR, str(r))

    # --- 14 authenticated empty map (R5 item 2) ------------------------------

    # The pinned ledger holds nine after: [] entries (all delete actions, e.g. id 2d1066c1b2ce).
    # An empty map WITH its recorded id is an observed state -> a valid basis.
    r = _out({}, {}, recorded="2d1066c1b2ce", tail="2d1066c1b2ce")
    check("14a authenticated empty map on both sides, fresh -> false (not unverified)",
          r["chain_break"] is False and r["chain_break_basis"] == P.BASIS_FRESHNESS, str(r))
    r = _out({PKG: X}, {}, recorded="2d1066c1b2ce", tail="2d1066c1b2ce")
    check("14b authenticated empty after-state + non-empty before -> true with the added path",
          r["chain_break"] is True and r["chain_break_paths"] == [PKG], str(r))
    r = _out({}, {}, recorded=None, tail="2d1066c1b2ce")
    check('14c empty map WITHOUT a recorded id -> "unverified"/no-sidecar (absent, not empty)',
          r["chain_break"] == "unverified" and r["chain_break_basis"] == P.BASIS_NO_SIDECAR, str(r))
    mm, mid = P.resolve_basis(memory_map={}, memory_id="2d1066c1b2ce", sidecar_map=None,
                              sidecar_id=None, sidecar_readable=False)
    check("14d an empty in-memory map with an id resolves as a basis, not as absence",
          mm == {} and mid == "2d1066c1b2ce", "%s %s" % (mm, mid))

    return executed, failures


def test_policy_controls_all_pass():
    executed, failures = _run_controls()
    assert failures == [], "policy control failures: %s" % failures
    assert executed == 29, f"expected 29 executed assertions, ran {executed}"


def test_controls_execute_all_29_assertions():
    """The ported acceptance set must stay at 29 executed assertions (revision 5)."""
    executed, _ = _run_controls()
    assert executed == 29


def test_artefact_re_matches_the_audit_rule():
    """The snapshot filter and the annotation comparison must agree on one artefact rule."""
    for p in ("a/__pycache__/x.pyc", "a/b.pyc", "a/b.pyo", "a/b.bak", "a/b.bak.2", "a/b.orig",
              "a/b~", "a/b.swp", "a/.DS_Store"):
        assert P.is_artefact(p), p
    for p in ("a/SKILL.md", "a/scripts/run.py", "a/backup.py", "a/notes.md", "a/swp.md"):
        assert not P.is_artefact(p), p


def test_drift_paths_reports_added_and_removed():
    assert P.drift_paths({"a": X}, {"b": X}) == ["a", "b"]
    assert P.drift_paths({"a": X}, {"a": X}) == []
    assert P.drift_paths({"a": X, "b": Y}, {"a": X}) == ["b"]


@pytest.mark.parametrize("kwargs", [
    dict(before_map=None, last_after_map=None, recorded_id=None, tail_id=None),
    dict(before_map={}, last_after_map={}, recorded_id="x", tail_id="x"),
    dict(before_map={}, last_after_map={}, recorded_id="x", tail_id="y"),
    dict(before_map={}, last_after_map={}, recorded_id=None, tail_id="x", tail_readable=False),
])
def test_outcome_key_set_is_always_the_three_keys(kwargs):
    r = P.chain_break_outcome(**kwargs)
    assert set(r) == {"chain_break", "chain_break_basis", "chain_break_paths"}
    assert r["chain_break"] in (True, False, "unverified")
