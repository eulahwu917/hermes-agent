"""`chain_break` annotation contract — the total outcome table, as a pure policy module.

Verbatim port of the canonical artifact `chain_break_policy_1.py` (card `t_7cc3bc69`,
revision 5, sha256 `738ebecd55b61a…`), landed by card `t_5c89799a` so the annotation the
ledger writes (`tools/skill_ledger.append_entry`) and the reviewer's acceptance controls
(`tests/tools/test_skill_ledger_chain.py`) both exercise the *same* table instead of an
implementation's own interpretation of it. Keep this module dependency-free and pure:
it takes facts and returns a verdict — it never reads the ledger, never writes, never
raises for well-typed input, and never blocks.

Contract
--------
`record_mutation` appends one key `chain_break` on **every** ledger entry, with
`chain_break_basis` and (when a difference was observed) `chain_break_paths`:

    false         the entry's captured `before` map equals this source's last-known `after`
                  map for the package and the ledger tail is fresh
    true          ... and they differ
    "unverified"  the comparison could not be established as a chain continuation: no
                  last-known map exists, the ledger tail could not be read, or another
                  process appended since this source's own last append

`"unverified"` must never be read as a break, and `true` is never claimed without freshness.

Facts, and where they come from
-------------------------------
* **last-known `after` map + the ledger id it was appended to.** Two provenances, resolved in
  this order by `resolve_basis` below: (1) the per-process **in-memory** record, populated
  **only** by this process's own successful appends while it is alive; (2) the durable
  per-package **sidecar**, written after each successful append and read **only when the
  in-memory record is absent** (a fresh CLI invocation). Both are *this source's own* append
  history; a map read from anywhere else is not a comparison basis.
* **ledger tail id.** Read inside the append path, immediately before the comparison.
* **the entry's captured `before` map.** Taken at capture time, before the write.

An **empty** map is a valid basis when it carries its recorded ledger id. The pinned ledger
really does hold nine `after: []` entries (all `delete` actions, e.g. id `2d1066c1b2ce` for
`personal-finance-analysis`), so emptiness is an *observed* state, not an unknown one. What
makes a basis unusable is the **absence** of a recorded state id (`recorded_id is None`) or of
a map at all (`last_after_map is None`) — never emptiness itself.

Provenance resolution and the sidecar (part of the contract)
------------------------------------------------------------
`resolve_basis(memory_map, memory_id, sidecar_map, sidecar_id, sidecar_readable)` returns the
(map, recorded id) pair the comparison uses:

1. the in-memory record, when this source has one for the package;
2. otherwise the durable sidecar, when it is readable and holds a recorded pair;
3. otherwise no basis at all.

Consequence, stated because round 3's prose and mandatory test disagreed about it: a process
with a **warm in-memory record** and a fresh tail returns `false`/`true` even if the sidecar
file has since been deleted or is unreadable. An unreadable sidecar is **not** by itself
`"unverified"` — `"unverified"`/`no-sidecar` requires that *neither* provenance yields a pair.
The mandatory sidecar-deleted test therefore carries the precondition "no in-memory record"
(a cold process); the warm-record/deleted-sidecar case is control 13 and must return
`false`/`true`.

Observation ordering (part of the contract)
-------------------------------------------
1. capture `before`;  2. write;  3. read the ledger tail id;  4. compare;  5. append with the
annotation;  6. update the in-memory record and the sidecar.

Consequences that the ordering makes explicit:

* Second process appends between A's *capture* and A's *freshness read* -> A sees a tail id it
  did not record -> `"unverified"`, never `true`.
* Second process appends **after** A's freshness read and before A's append -> **documented
  non-coverage** (residual). A stale-tail read cannot observe an append that has not happened
  yet, so the policy *does* still produce `true` for a real difference in that case (control 12
  states the outcome; it does not demonstrate a guarantee). The module's contract is "never
  block the mutation", so this is bounded, not fixed.
* Derived artefacts (`__pycache__/*.pyc`, editor droppings) are ignored on both sides of the
  comparison, so interpreter churn inside a package never produces `true`.

Concurrency scope
-----------------
The freshness check is a **cross-process** check (it reads the shared ledger tail), not a
lock. It *annotates*; it does not serialise. No claim of "the interleaves are fixed" is made
or implied.
"""
from __future__ import annotations

import re

CHAIN_BREAK_TRUE = True
CHAIN_BREAK_FALSE = False
CHAIN_BREAK_UNVERIFIED = "unverified"

BASIS_FRESHNESS = "freshness"
BASIS_STALE_SIDECAR = "stale-sidecar"
BASIS_NO_SIDECAR = "no-sidecar"

# Same artefact rule as the audit's snapshot filter and `ledger_audit.ARTIFACT_RE`.
ARTEFACT_RE = re.compile(
    r"(^|/)(__pycache__/|.*\.pyc$|.*\.pyo$|.*\.bak(\..*)?$|.*\.orig$|.*~$|.*\.swp$|\.DS_Store$)")


def is_artefact(path: str) -> bool:
    return bool(ARTEFACT_RE.search(path or ""))


def resolve_basis(*, memory_map, memory_id, sidecar_map, sidecar_id, sidecar_readable=True):
    """Resolve the last-known `after` map and its recorded ledger id from the two provenances.

    Contract order (see the module docstring): the warm in-memory record first; the durable
    sidecar only when there is no in-memory record; otherwise no basis. Returns
    `(last_after_map, recorded_id)`, either of which may be None.

    An empty map is returned as-is when it carries an id: emptiness is an observed state, not
    an absent one. `sidecar_readable=False` models a deleted/unreadable sidecar file and can
    only matter when the in-memory record is absent.
    """
    if memory_map is not None or memory_id is not None:
        return memory_map, memory_id
    if sidecar_readable and (sidecar_map is not None or sidecar_id is not None):
        return sidecar_map, sidecar_id
    return None, None


def drift_paths(before_map: dict | None, last_after_map: dict | None) -> list:
    """Paths differing between two {path: sha} maps, ignoring derived artefacts.

    A path present on one side only counts (added / removed). Returns a sorted list.
    """
    before_map = before_map or {}
    last_after_map = last_after_map or {}
    out = []
    for p in set(before_map) | set(last_after_map):
        if is_artefact(p):
            continue
        if before_map.get(p) != last_after_map.get(p):
            out.append(p)
    return sorted(out)


def chain_break_outcome(*, before_map, last_after_map, recorded_id, tail_id,
                        tail_readable=True):
    """The single, total outcome table. -> dict with the three keys the append path writes.

    Arguments are facts gathered at step 3-4 of the ordering above:

    before_map      - the entry's captured {path: sha} `before` map
    last_after_map  - this source's last-known `after` map for the package, or None when no
                      in-memory record and no readable sidecar record exist. An authenticated
                      **empty** map ({}) is a valid basis, not an absent one.
    recorded_id     - the ledger id recorded alongside *last_after_map*, or None
    tail_id         - the ledger's current tail id
    tail_readable   - False when the ledger tail could not be read at all

    Every combination is defined; there is no other permitted field combination.
    """
    # Row 5/6: no comparison basis at all (cold process, first entry for the package, or a
    # sidecar that is absent/unreadable *and* no in-memory record). The test is the absence of
    # a recorded state id or of a map - never emptiness: an authenticated {} with its ledger id
    # is a real observed state (the pinned ledger holds nine after: [] entries) and is compared
    # normally.
    if last_after_map is None or recorded_id is None:
        return {"chain_break": CHAIN_BREAK_UNVERIFIED, "chain_break_basis": BASIS_NO_SIDECAR,
                "chain_break_paths": []}

    paths = drift_paths(before_map, last_after_map)

    # Freshness unavailable (unreadable ledger tail): a difference cannot be certified.
    if not tail_readable or tail_id is None:
        return {"chain_break": CHAIN_BREAK_UNVERIFIED, "chain_break_basis": BASIS_NO_SIDECAR,
                "chain_break_paths": paths}

    # Another writer appended since this source's own last append: the comparison basis is
    # stale, so neither `true` nor `false` may be claimed (this resolves rev 3's stale+equal
    # contradiction: the table and the second-process test now agree).
    if tail_id != recorded_id:
        return {"chain_break": CHAIN_BREAK_UNVERIFIED,
                "chain_break_basis": BASIS_STALE_SIDECAR, "chain_break_paths": paths}

    # Fresh tail: the only case that may claim a verdict.
    if paths:
        return {"chain_break": CHAIN_BREAK_TRUE, "chain_break_basis": BASIS_FRESHNESS,
                "chain_break_paths": paths}
    return {"chain_break": CHAIN_BREAK_FALSE, "chain_break_basis": BASIS_FRESHNESS,
            "chain_break_paths": []}
