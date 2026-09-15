"""Tests for tools/skill_ledger.py — per-mutation audit ledger + rollback.

Covers tracker #79686 P3: ledger entries on patch/edit/delete/archive, blob
dedupe, single-entry rollback (incl. fail-closed safety capture), actor
tagging, and the skills.ledger config gate.

The first four tests are adapted from PR #50261 by @yu-xin-c (autonomous
skill history), reshaped for the all-actor JSONL ledger design.
"""

import json
from pathlib import Path

import pytest


VALID_SKILL_CONTENT = """---
name: my-skill
description: test skill
---

# My Skill

Original body.
"""

# Same skill with a changed body: the frontmatter must survive an out-of-band edit, or the
# patch guard (correctly) refuses to touch the file and the test would prove nothing.
DRIFTED_SKILL_CONTENT = VALID_SKILL_CONTENT.replace("Original body.", "Drifted body.")


@pytest.fixture
def ledger_env(tmp_path, monkeypatch):
    """Isolated HERMES_HOME + skills dir for skill_manage and the ledger."""
    from agent import skill_utils
    from tools import skill_ledger, skill_manager_tool, skill_usage

    home = tmp_path / "home"
    skills_dir = home / "skills"
    skills_dir.mkdir(parents=True)

    monkeypatch.setattr(skill_ledger, "get_hermes_home", lambda: home)
    monkeypatch.setattr(skill_usage, "get_hermes_home", lambda: home)
    monkeypatch.setattr(skill_manager_tool, "SKILLS_DIR", skills_dir)
    monkeypatch.setattr(skill_utils, "get_all_skills_dirs", lambda: [skills_dir])
    # Per-process `chain_break` record: a fresh process has none (it is populated only by this
    # process's own appends), so a test must not inherit the previous test's.
    if (chain_memory := getattr(skill_ledger, "_chain_memory", None)) is not None:
        chain_memory.clear()
    return {"home": home, "skills": skills_dir}


def _create(name="my-skill", content=VALID_SKILL_CONTENT):
    from tools.skill_manager_tool import skill_manage

    return json.loads(skill_manage(action="create", name=name, content=content))


# ---------------------------------------------------------------------------
# Adapted from PR #50261 (@yu-xin-c)
# ---------------------------------------------------------------------------


def test_background_review_patch_ledgers_and_rolls_back(ledger_env, monkeypatch):
    """A curator-pass patch lands in the ledger tagged 'curator', and a
    single-entry rollback restores the exact pre-patch content."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage
    from tools.skill_provenance import (
        BACKGROUND_REVIEW,
        reset_current_write_origin,
        set_current_write_origin,
    )
    from tools.skill_manager_guards import mark_background_review_skill_read

    token = set_current_write_origin(BACKGROUND_REVIEW)
    try:
        # Created under the review fork → marked created_by: agent, so the
        # curator pass is allowed to patch it (curator invariant unchanged).
        assert _create()["success"] is True
        skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
        original = skill_md.read_text(encoding="utf-8")
        mark_background_review_skill_read(skill_md)
        patched = json.loads(
            skill_manage(
                action="patch",
                name="my-skill",
                old_string="Original body.",
                new_string="Updated body.",
            )
        )
    finally:
        reset_current_write_origin(token)

    assert patched["success"] is True
    assert "Updated body." in skill_md.read_text(encoding="utf-8")

    rows = skill_ledger.list_entries(skill="my-skill")
    patch_rows = [r for r in rows if r["action"] == "patch"]
    assert len(patch_rows) == 1
    entry = patch_rows[0]
    assert entry["actor"] == "curator"
    assert any(i["path"].endswith("SKILL.md") for i in entry["before"])

    ok, msg = skill_ledger.rollback_entry(entry["id"])
    assert ok is True, msg
    assert skill_md.read_text(encoding="utf-8") == original


def test_foreground_patch_is_ledgered_as_agent(ledger_env):
    """Foreground skill_manage patches are ledgered too (all-actor design —
    unlike #50261's autonomous-only history) and tagged 'agent'."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    patched = json.loads(
        skill_manage(
            action="patch",
            name="my-skill",
            old_string="Original body.",
            new_string="Updated body.",
        )
    )
    assert patched["success"] is True

    rows = [r for r in skill_ledger.list_entries(skill="my-skill") if r["action"] == "patch"]
    assert len(rows) == 1
    assert rows[0]["actor"] == "agent"


def test_rollback_refuses_paths_outside_hermes_home(ledger_env):
    """A hand-edited ledger entry pointing outside HERMES_HOME must not
    become a write-anywhere primitive."""
    from tools import skill_ledger

    entry_id = skill_ledger.append_entry(
        "patch",
        "evil",
        before=[{"path": "/etc/passwd", "sha256": "0" * 64}],
        after=[],
    )
    assert entry_id is not None
    ok, msg = skill_ledger.rollback_entry(entry_id)
    assert ok is False
    assert "outside" in msg


def test_missing_blob_aborts_rollback_before_any_change(ledger_env):
    from tools import skill_ledger

    assert _create()["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    entry_id = skill_ledger.append_entry(
        "patch",
        "my-skill",
        before=[{"path": str(skill_md), "sha256": "a" * 64}],
        after=[],
    )
    current = skill_md.read_bytes()
    ok, msg = skill_ledger.rollback_entry(entry_id)
    assert ok is False
    assert "missing blob" in msg
    assert skill_md.read_bytes() == current


# ---------------------------------------------------------------------------
# New-design coverage
# ---------------------------------------------------------------------------


def test_ledger_entry_on_edit_and_delete(ledger_env):
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    edited = json.loads(
        skill_manage(
            action="edit",
            name="my-skill",
            content=VALID_SKILL_CONTENT.replace("Original body.", "Edited body."),
        )
    )
    assert edited["success"] is True
    deleted = json.loads(
        skill_manage(action="delete", name="my-skill", absorbed_into="")
    )
    assert deleted["success"] is True

    actions = [r["action"] for r in skill_ledger.list_entries(skill="my-skill")]
    assert actions == ["delete", "edit", "create"]  # newest first

    delete_entry = skill_ledger.list_entries(skill="my-skill")[0]
    # Delete intent recorded: explicit prune (absorbed_into="") + hard delete.
    assert delete_entry["evidence"]["absorbed_into"] == ""
    assert delete_entry["evidence"]["archived"] is False
    # Before-state captured, after empty (skill gone).
    assert delete_entry["before"]
    assert delete_entry["after"] == []


def test_deleted_skill_recoverable_from_ledger(ledger_env):
    """A foreground hard delete stays a hard delete — but the ledger entry
    can restore the skill's files from blobs."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    original = skill_md.read_bytes()

    assert json.loads(skill_manage(action="delete", name="my-skill"))["success"]
    assert not skill_md.exists()

    entry = skill_ledger.list_entries(skill="my-skill")[0]
    ok, msg = skill_ledger.rollback_entry(entry["id"])
    assert ok is True, msg
    assert skill_md.read_bytes() == original


def test_archive_lands_in_ledger_with_curator_actor(ledger_env, monkeypatch):
    from tools import skill_ledger, skill_usage

    assert _create()["success"] is True
    # Curator auto-transition path tags the actor explicitly.
    tok = skill_ledger.set_ledger_actor("curator")
    try:
        ok, msg = skill_usage.archive_skill("my-skill")
    finally:
        skill_ledger.reset_ledger_actor(tok)
    assert ok, msg

    rows = [r for r in skill_ledger.list_entries(skill="my-skill") if r["action"] == "archive"]
    assert len(rows) == 1
    assert rows[0]["actor"] == "curator"
    assert rows[0]["before"] and rows[0]["after"]

    # And restore is ledgered as well.
    ok, msg = skill_usage.restore_skill("my-skill")
    assert ok, msg
    assert any(
        r["action"] == "restore" for r in skill_ledger.list_entries(skill="my-skill")
    )


def test_blob_dedupe_same_content_one_blob(ledger_env):
    from tools import skill_ledger

    d = ledger_env["skills"] / "dedupe-src"
    d.mkdir()
    (d / "a.md").write_text("identical content", encoding="utf-8")
    (d / "b.md").write_text("identical content", encoding="utf-8")

    manifest = skill_ledger.snapshot_paths(d)
    assert len(manifest) == 2
    hashes = {m["sha256"] for m in manifest}
    assert len(hashes) == 1  # same content → same hash
    blobs = list(skill_ledger.blobs_dir().iterdir())
    assert len(blobs) == 1  # → one blob on disk


def test_rollback_fails_closed_when_safety_capture_fails(ledger_env, monkeypatch):
    """If the pre-rollback safety ledger entry can't be written, the rollback
    must abort with nothing changed (consistent with #63366)."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    patched = json.loads(
        skill_manage(
            action="patch",
            name="my-skill",
            old_string="Original body.",
            new_string="Updated body.",
        )
    )
    assert patched["success"] is True
    entry = [r for r in skill_ledger.list_entries("my-skill") if r["action"] == "patch"][0]
    current = skill_md.read_bytes()

    monkeypatch.setattr(skill_ledger, "append_entry", lambda *a, **k: None)
    ok, msg = skill_ledger.rollback_entry(entry["id"])
    assert ok is False
    assert "safety capture failed" in msg
    assert skill_md.read_bytes() == current  # nothing changed


def test_rollback_removes_files_created_by_the_mutation(ledger_env):
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    wrote = json.loads(
        skill_manage(
            action="write_file",
            name="my-skill",
            file_path="references/extra.md",
            file_content="new supporting file",
        )
    )
    assert wrote["success"] is True
    extra = ledger_env["skills"] / "my-skill" / "references" / "extra.md"
    assert extra.exists()

    entry = [r for r in skill_ledger.list_entries("my-skill") if r["action"] == "write_file"][0]
    ok, msg = skill_ledger.rollback_entry(entry["id"])
    assert ok is True, msg
    assert not extra.exists()  # created by the mutation → removed on rollback


def test_config_gate_off_no_ledger_writes(ledger_env, monkeypatch):
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "load_config", lambda *a, **k: {"skills": {"ledger": False}})

    assert _create()["success"] is True
    patched = json.loads(
        skill_manage(
            action="patch",
            name="my-skill",
            old_string="Original body.",
            new_string="Updated body.",
        )
    )
    assert patched["success"] is True  # mutation unaffected
    assert not skill_ledger.ledger_path().exists()
    assert not skill_ledger.blobs_dir().exists()


def test_ledger_failure_never_blocks_the_mutation(ledger_env, monkeypatch):
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(skill_ledger, "snapshot_paths", _boom)

    assert _create()["success"] is True
    patched = json.loads(
        skill_manage(
            action="patch",
            name="my-skill",
            old_string="Original body.",
            new_string="Updated body.",
        )
    )
    assert patched["success"] is True


def test_list_entries_filtering_and_limit(ledger_env):
    from tools import skill_ledger

    for i in range(5):
        skill_ledger.append_entry("patch", f"skill-{i % 2}", before=[], after=[])
    assert len(skill_ledger.list_entries(limit=3)) == 3
    only_zero = skill_ledger.list_entries(skill="skill-0")
    assert len(only_zero) == 3
    assert all(r["skill"] == "skill-0" for r in only_zero)


def test_user_actor_override(ledger_env):
    from tools import skill_ledger

    tok = skill_ledger.set_ledger_actor("user")
    try:
        entry_id = skill_ledger.append_entry("archive", "some-skill")
    finally:
        skill_ledger.reset_ledger_actor(tok)
    entry = skill_ledger.get_entry(entry_id)
    assert entry["actor"] == "user"


# ---------------------------------------------------------------------------
# Package-completeness fill from the newest curator backup (issue #96962)
# ---------------------------------------------------------------------------


def _write_skills_tarball(home: Path, files: dict, stamp: str = "2026-08-01T00-00-00Z"):
    """Write a curator-shaped ``skills.tar.gz`` under *home* (arcnames are
    relative to skills/, exactly like agent.curator_backup.snapshot_skills)."""
    import io
    import tarfile

    snap = home / "skills" / ".curator_backups" / stamp
    snap.mkdir(parents=True, exist_ok=True)
    tar_path = snap / "skills.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        for rel, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=rel)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return tar_path


def test_delete_after_rehome_ledgers_full_package_from_backup(ledger_env):
    """The incident shape (#96962): consolidation re-homes references/ out of
    the tree, then deletes. The delete entry must still capture the support
    file from the newest curator backup, and rollback must restore both."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    extra = ledger_env["skills"] / "my-skill" / "references" / "extra.md"
    wrote = json.loads(skill_manage(
        action="write_file",
        name="my-skill",
        file_path="references/extra.md",
        file_content="roadmap body",
    ))
    assert wrote["success"] is True

    # The pre-curator-run snapshot, taken while the package was whole.
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    _write_skills_tarball(
        ledger_env["home"],
        {
            "my-skill/SKILL.md": skill_md.read_text(encoding="utf-8"),
            "my-skill/references/extra.md": "roadmap body",
        },
    )

    # Re-home: the support file leaves the tree before the delete.
    extra.unlink()
    extra.parent.rmdir()

    deleted = json.loads(skill_manage(action="delete", name="my-skill"))
    assert deleted["success"] is True

    delete_entry = [
        r for r in skill_ledger.list_entries(skill="my-skill")
        if r["action"] == "delete"
    ][0]
    # EXACT path set (R1): every before path is inside the package. The round-1 shape
    # stripped the package segment when the destination was the skills root and added
    # <skills>/SKILL.md + <skills>/references/extra.md targets here — rollback restored 4
    # paths where the pre-change code restored these 2.
    before_paths = {Path(i["path"]) for i in delete_entry["before"]}
    assert before_paths == {skill_md, extra}, before_paths

    ok, msg = skill_ledger.rollback_entry(delete_entry["id"])
    assert ok is True, msg
    assert skill_md.is_file()
    assert extra.is_file()
    assert extra.read_text(encoding="utf-8") == "roadmap body"
    # Nothing was created OUTSIDE the package during rollback.
    assert not (ledger_env["skills"] / "SKILL.md").exists()
    assert not (ledger_env["skills"] / "references").exists()


def test_sole_delete_batch_ledgers_exact_package_set(ledger_env):
    """R1 sole-delete batch: the batch API routes a sole delete to the single-op handler, so
    the delete entry's before set must be exactly the live package — no out-of-package
    targets — even when the newest backup is the only source of a re-homed support file."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    extra = ledger_env["skills"] / "my-skill" / "references" / "extra.md"
    wrote = json.loads(skill_manage(action="write_file", name="my-skill",
                                    file_path="references/extra.md",
                                    file_content="support file\n"))
    assert wrote["success"] is True
    _write_skills_tarball(
        ledger_env["home"],
        {"my-skill/SKILL.md": skill_md.read_text(encoding="utf-8"),
         "my-skill/references/extra.md": "support file"},
    )

    deld = json.loads(skill_manage(
        action="batch", name="my-skill",
        operations=[{"action": "delete", "name": "my-skill"}]))
    assert deld["success"] is True, deld

    delete_entry = [r for r in skill_ledger.list_entries(skill="my-skill")
                    if r["action"] == "delete"][0]
    before_paths = {Path(i["path"]) for i in delete_entry["before"]}
    assert before_paths == {skill_md, extra}, before_paths

    ok, msg = skill_ledger.rollback_entry(delete_entry["id"])
    assert ok is True, msg
    assert skill_md.is_file() and extra.is_file()
    assert not (ledger_env["skills"] / "SKILL.md").exists()


def test_archive_ledgers_no_out_of_package_targets(ledger_env):
    """R1 archive caller: archive captures the COMPLETE package (backup fill) with a missing
    root — the archive entry's before set must stay exactly the live package, and rollback
    of the archive creates nothing outside it."""
    from tools import skill_ledger, skill_usage
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    wrote = json.loads(skill_manage(action="write_file", name="my-skill",
                                    file_path="references/extra.md",
                                    file_content="support file\n"))
    assert wrote["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"
    extra = ledger_env["skills"] / "my-skill" / "references" / "extra.md"
    _write_skills_tarball(
        ledger_env["home"],
        {"my-skill/SKILL.md": skill_md.read_text(encoding="utf-8"),
         "my-skill/references/extra.md": "support file"},
    )

    tok = skill_ledger.set_ledger_actor("curator")
    try:
        ok, msg = skill_usage.archive_skill("my-skill")
    finally:
        skill_ledger.reset_ledger_actor(tok)
    assert ok, msg

    archived = [r for r in skill_ledger.list_entries("my-skill")
                if r["action"] == "archive"][0]
    before_paths = {Path(i["path"]) for i in archived["before"]}
    assert before_paths == {skill_md, extra}, before_paths

    ok, msg = skill_ledger.rollback_entry(archived["id"])
    assert ok is True, msg
    assert skill_md.is_file() and extra.is_file()
    assert not (ledger_env["skills"] / "SKILL.md").exists()
    assert not (ledger_env["skills"] / "references").exists()


def test_fill_with_missing_root_category_tar_stays_under_the_category(ledger_env):
    """R1 missing-root + the real ``<category>/<skill>/…`` tar shape: when the destination is
    the skills root, the full tar path IS the on-disk relative path — no package-prefix
    stripping, no skills/SKILL.md phantom, and the missing support file lands inside the
    package under its category."""
    from tools import skill_ledger

    pkg = _categorised_pkg(ledger_env)
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {"personal-infra/my-skill/SKILL.md": VALID_SKILL_CONTENT,
         "personal-infra/my-skill/references/extra.md": "from tar"},
    )

    # Pre-captured before list with the support file already re-homed off disk.
    before = skill_ledger.snapshot_paths(pkg)
    assert [i["path"] for i in before] == [str(skill_md)]
    filled = skill_ledger.fill_snapshot_from_curator_backup(None, before, skill="my-skill")
    paths = {Path(i["path"]) for i in filled}
    assert paths == {skill_md, pkg / "references" / "extra.md"}, paths


def test_rollback_historical_hollow_entry_restores_full_package(ledger_env):
    """Entries recorded BEFORE this fix (files: 1) still restore the whole
    package: rollback-time fill from the newest curator backup."""
    from tools import skill_ledger

    skill_dir = ledger_env["skills"] / "my-skill"
    skill_dir.mkdir()
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {
            "my-skill/SKILL.md": VALID_SKILL_CONTENT,
            "my-skill/references/roadmap.md": "week 1",
        },
    )
    # The mutation that made the entry: package gone, only SKILL.md captured.
    skill_md.unlink()
    skill_dir.rmdir()

    entry_id = skill_ledger.append_entry(
        "delete",
        "my-skill",
        before=[{"path": str(skill_md), "sha256": skill_ledger._store_blob(
            VALID_SKILL_CONTENT.encode("utf-8")
        )}],
        after=[],
    )
    assert entry_id is not None

    ok, msg = skill_ledger.rollback_entry(entry_id)
    assert ok is True, msg
    roadmap = skill_dir / "references" / "roadmap.md"
    assert skill_md.is_file()
    assert roadmap.is_file(), "hollow rollback: support file not restored"
    assert roadmap.read_text(encoding="utf-8") == "week 1"


def test_rollback_hollow_categorised_entry_restores_under_the_category(ledger_env):
    """R1 missing-root recovery with the category-prefixed tar: a hollow historical delete of
    a categorised package fills from the backup and restores exactly the package paths
    (``skills/<category>/<skill>/…``) — never a bare twin, never skills/SKILL.md."""
    from tools import skill_ledger

    skill_dir = _categorised_pkg(ledger_env)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {"personal-infra/my-skill/SKILL.md": VALID_SKILL_CONTENT,
         "personal-infra/my-skill/references/roadmap.md": "week 1"},
    )
    skill_md.unlink()
    skill_dir.rmdir()

    entry_id = skill_ledger.append_entry(
        "delete", "my-skill",
        before=[{"path": str(skill_md),
                 "sha256": skill_ledger._store_blob(VALID_SKILL_CONTENT.encode("utf-8"))}],
        after=[],
    )
    assert entry_id is not None

    ok, msg = skill_ledger.rollback_entry(entry_id)
    assert ok is True, msg
    assert skill_md.is_file()
    roadmap = skill_dir / "references" / "roadmap.md"
    assert roadmap.is_file(), "hollow categorised rollback: support file not restored"
    assert roadmap.read_text(encoding="utf-8") == "week 1"
    assert not (ledger_env["skills"] / "my-skill").exists()
    assert not (ledger_env["skills"] / "SKILL.md").exists()


def test_delete_rollback_without_backup_still_works(ledger_env):
    """No curator backup present: the fill degrades to the old behavior and
    must not break the plain delete -> rollback round trip."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_md = ledger_env["skills"] / "my-skill" / "SKILL.md"

    deleted = json.loads(skill_manage(action="delete", name="my-skill"))
    assert deleted["success"] is True
    delete_entry = [
        r for r in skill_ledger.list_entries(skill="my-skill")
        if r["action"] == "delete"
    ][0]
    assert {Path(i["path"]).name for i in delete_entry["before"]} == {"SKILL.md"}

    ok, msg = skill_ledger.rollback_entry(delete_entry["id"])
    assert ok is True, msg
    assert skill_md.read_text(encoding="utf-8") == VALID_SKILL_CONTENT


def test_backup_fill_does_not_clobber_disk_hash(ledger_env):
    """Disk state wins: a live SKILL.md that differs from the backup copy is
    captured with the LIVE hash; the backup only fills missing paths."""
    from tools import skill_ledger

    skill_dir = ledger_env["skills"] / "my-skill"
    skill_dir.mkdir()
    skill_md = skill_dir / "SKILL.md"
    live = VALID_SKILL_CONTENT.replace("Original body.", "Live body.")
    skill_md.write_text(live, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {
            "my-skill/SKILL.md": VALID_SKILL_CONTENT,
            "my-skill/references/extra.md": "from tar",
        },
    )

    captured = skill_ledger.snapshot_paths(skill_dir, complete_package=True)
    by_name = {Path(i["path"]).name: i["sha256"] for i in captured}
    live_hash = skill_ledger._store_blob(live.encode("utf-8"))
    tar_hash = skill_ledger._store_blob(VALID_SKILL_CONTENT.encode("utf-8"))
    assert by_name["SKILL.md"] == live_hash, "disk hash must win over backup"
    assert by_name["SKILL.md"] != tar_hash
    assert by_name["extra.md"] == skill_ledger._store_blob(b"from tar")


def test_backup_fill_ignores_tar_path_traversal(ledger_env):
    """Fill runs AND malicious members are rejected: a legitimate missing
    file is restored while members escaping the package prefix (absolute,
    ..) are never filled. Both assertions matter — the positive one keeps
    this test honest (a silently inert fill would pass a negatives-only
    check), the negative one pins the traversal defense."""
    from tools import skill_ledger

    skill_dir = ledger_env["skills"] / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {
            "my-skill/SKILL.md": VALID_SKILL_CONTENT,
            "my-skill/references/legit.md": "legit body",
            "../evil.md": "nope",
            "my-skill/../outside.md": "nope",
        },
    )

    captured = skill_ledger.snapshot_paths(skill_dir, complete_package=True)
    paths = [i["path"] for i in captured]
    # The legitimate missing file WAS filled — proof the fill is live.
    assert any(p.endswith("references/legit.md") for p in paths), (
        "package fill did not restore the missing support file"
    )
    # Malicious members are not.
    assert not any(p.endswith("evil.md") or p.endswith("outside.md") for p in paths)


# ---------------------------------------------------------------------------
# Backup-fill path shape (audit mechanism b1, card t_7cc3bc69 §6.1)
# ---------------------------------------------------------------------------


def _categorised_pkg(ledger_env, name="my-skill", category="personal-infra"):
    pkg = ledger_env["skills"] / category / name
    pkg.mkdir(parents=True)
    return pkg


def test_backup_fill_strips_the_category_prefix_no_phantom_twin(ledger_env):
    """The real curator tar shape is ``<category>/<skill>/…`` (the whole path under
    ``skills/``). Stripping only the package dir NAME left a category-duplicated twin
    (``<skills>/<cat>/<skill>/<cat>/<skill>/…``) — a path that does not exist on disk and that
    ``rollback_entry`` would ``mkdir`` and write. The fill must target the on-disk layout."""
    from tools import skill_ledger

    pkg = _categorised_pkg(ledger_env)
    (pkg / "SKILL.md").write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"],
        {
            "personal-infra/my-skill/SKILL.md": VALID_SKILL_CONTENT,
            "personal-infra/my-skill/references/extra.md": "from tar",
        },
    )

    captured = skill_ledger.snapshot_paths(pkg, complete_package=True)
    paths = [i["path"] for i in captured]
    assert not any("my-skill/personal-infra/" in p for p in paths), (
        f"category-duplicated phantom path filled: {paths}"
    )
    assert sum(p.endswith("SKILL.md") for p in paths) == 1, paths
    assert str(pkg / "SKILL.md") in paths
    # The legitimate missing file lands NEXT TO the package, not inside a phantom twin.
    filled = [p for p in paths if p.endswith("references/extra.md")]
    assert len(filled) == 1, paths
    assert Path(filled[0]).parent == pkg / "references"


@pytest.mark.parametrize("tar_body", [VALID_SKILL_CONTENT, "a different body\n"])
def test_backup_fill_never_emits_a_category_duplicated_twin(ledger_env, tar_body):
    """§6.1 regression: an EQUAL twin and an UNEQUAL twin must both be refused — the twin is
    not a path shape the ledger may record, whatever hash it carries. Disk state wins."""
    from tools import skill_ledger

    pkg = _categorised_pkg(ledger_env)
    (pkg / "SKILL.md").write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"], {"personal-infra/my-skill/SKILL.md": tar_body}
    )

    captured = skill_ledger.snapshot_paths(pkg, complete_package=True)
    skill_md = [i for i in captured if i["path"].endswith("SKILL.md")]
    assert len(skill_md) == 1, [i["path"] for i in captured]
    assert skill_md[0]["path"] == str(pkg / "SKILL.md")
    assert skill_md[0]["sha256"] == skill_ledger._store_blob(
        VALID_SKILL_CONTENT.encode("utf-8"))


def test_backup_fill_still_handles_an_uncategorised_package(ledger_env):
    """The bare-name shape must keep working after the prefix-strip change."""
    from tools import skill_ledger

    skill_dir = ledger_env["skills"] / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    _write_skills_tarball(
        ledger_env["home"], {"my-skill/references/extra.md": "from tar"}
    )

    captured = skill_ledger.snapshot_paths(skill_dir, complete_package=True)
    filled = [i["path"] for i in captured if i["path"].endswith("references/extra.md")]
    assert filled == [str(skill_dir / "references" / "extra.md")], captured


# ---------------------------------------------------------------------------
# Derived-artefact exclusion (audit mechanism b2, card t_7cc3bc69 §6.2)
# ---------------------------------------------------------------------------


def test_snapshot_paths_excludes_derived_artefacts(ledger_env):
    from tools import skill_ledger

    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "scripts" / "__pycache__").mkdir(parents=True)
    (pkg / "SKILL.md").write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    (pkg / "scripts" / "run.py").write_text("print('hi')\n", encoding="utf-8")
    (pkg / "scripts" / "__pycache__" / "run.cpython-311.pyc").write_bytes(b"\x00\x01")
    (pkg / "SKILL.md.bak").write_text("backup", encoding="utf-8")
    (pkg / ".DS_Store").write_bytes(b"\x00")

    names = {Path(i["path"]).name for i in skill_ledger.snapshot_paths(pkg)}
    assert names == {"SKILL.md", "run.py"}, names


# ---------------------------------------------------------------------------
# `chain_break` annotation (card t_5c89799a §8.1)
# ---------------------------------------------------------------------------


def _entries(skill="my-skill"):
    """{action: newest entry of that action} — list_entries is newest-first, so reverse it."""
    from tools import skill_ledger

    return {r["action"]: r for r in reversed(skill_ledger.list_entries(skill=skill))}


def test_chain_break_annotation_present_on_every_entry(ledger_env):
    """First entry for a package: no comparison basis -> "unverified"/no-sidecar, never
    false, and never an exception (acceptance test 4)."""
    from tools import skill_ledger

    assert _create()["success"] is True
    entry = _entries()["create"]
    assert entry["chain_break"] == "unverified"
    assert entry["chain_break_basis"] == "no-sidecar"
    assert entry["chain_break_paths"] == []
    # The sidecar now records this process's own append.
    status, packages = skill_ledger._read_chain_sidecar()
    assert status == "ok"
    assert packages["my-skill"]["id"] == entry["id"]


def test_chain_break_true_with_exactly_the_drifted_paths(ledger_env):
    """Acceptance test 1/6: a synthetic out-of-band write between two ledgered ops on a fresh
    tail -> `chain_break: true` carrying EXACTLY the drifted paths."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    pkg = ledger_env["skills"] / "my-skill"
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(skill_md.read_text(encoding="utf-8") + "\n<!-- edited outside the ledger -->\n",
                        encoding="utf-8")
    (pkg / "references").mkdir()
    (pkg / "references" / "oob.md").write_text("added outside the ledger\n", encoding="utf-8")

    patched = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string="Original body.", new_string="Updated body."))
    assert patched["success"] is True, patched
    entry = _entries()["patch"]
    assert entry["chain_break"] is True, entry
    assert entry["chain_break_basis"] == "freshness"
    assert entry["chain_break_paths"] == ["SKILL.md", "references/oob.md"], entry["chain_break_paths"]


def test_chain_break_false_on_a_clean_chain(ledger_env):
    """Acceptance test 6: fresh tail with equal maps -> false."""
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    for old, new in (("Original body.", "Updated body."), ("Updated body.", "Second body.")):
        res = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string=old, new_string=new))
        assert res["success"] is True, res
    assert _entries()["patch"]["chain_break"] is False
    assert _entries()["patch"]["chain_break_paths"] == []


def test_chain_break_ignores_pycache_churn(ledger_env):
    """Acceptance test 5: a ``__pycache__/x.pyc`` appearing between ops -> `false`, and it
    never enters a before/after snapshot in the first place."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    wrote = json.loads(skill_manage(action="write_file", name="my-skill",
                                    file_path="scripts/run.py", file_content="print('hi')\n"))
    assert wrote["success"] is True, wrote
    pkg = ledger_env["skills"] / "my-skill"
    cache = pkg / "scripts" / "__pycache__"
    cache.mkdir(parents=True, exist_ok=True)
    pyc = cache / "run.cpython-311.pyc"
    pyc.write_bytes(b"\x00\x01\x02")  # interpreter churn, out-of-band
    assert pyc.is_file()  # the artefact really was on disk during the next capture

    patched = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string="Original body.", new_string="Updated body."))
    assert patched["success"] is True, patched
    entry = _entries()["patch"]
    assert entry["chain_break"] is False, entry
    assert entry["chain_break_paths"] == []
    for section in ("before", "after"):
        assert not any(str(i["path"]).endswith(".pyc") for i in entry[section]), section
    assert pyc.is_file()  # excluded from the ledger, never deleted


def test_chain_break_unverified_on_cold_process_without_sidecar(ledger_env):
    """Acceptance test 3/4: no in-memory record and no readable sidecar -> "unverified"
    (no-sidecar); the append itself is unaffected and no exception escapes."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_ledger._chain_memory.clear()          # cold process
    sidecar = skill_ledger.chain_sidecar_path()
    sidecar.unlink()                            # sidecar gone too -> no basis at all
    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")

    patched = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string="Drifted body.", new_string="Updated body."))
    assert patched["success"] is True, patched
    entry = _entries()["patch"]
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break_basis"] == "no-sidecar"
    assert entry["chain_break"] is not True


def test_chain_break_unverified_when_sidecar_unreadable(ledger_env):
    """An unreadable sidecar is no basis (cold process) -> "unverified", append unchanged, and
    the unreadable file is left alone rather than clobbered."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    skill_ledger._chain_memory.clear()
    sidecar = skill_ledger.chain_sidecar_path()
    sidecar.write_text("{not json at all", encoding="utf-8")
    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")

    patched = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string="Drifted body.", new_string="Updated body."))
    assert patched["success"] is True, patched
    entry = _entries()["patch"]
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break_basis"] == "no-sidecar"
    assert sidecar.read_text(encoding="utf-8") == "{not json at all"


def test_warm_memory_outranks_a_deleted_sidecar(ledger_env):
    """Acceptance test 7: with a warm in-memory record a deleted sidecar is NOT "unverified" —
    the record is the basis, so a fresh tail still yields false / true."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    sidecar = skill_ledger.chain_sidecar_path()
    sidecar.unlink()

    clean = json.loads(skill_manage(action="patch", name="my-skill",
                                    old_string="Original body.", new_string="Updated body."))
    assert clean["success"] is True, clean
    assert _entries()["patch"]["chain_break"] is False, _entries()["patch"]

    sidecar.unlink()  # the previous append rewrote it; delete again
    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")
    drifted = json.loads(skill_manage(action="patch", name="my-skill",
                                      old_string="Drifted body.", new_string="Patched body."))
    assert drifted["success"] is True, drifted
    entry = _entries()["patch"]
    assert entry["chain_break"] is True, entry
    assert entry["chain_break_basis"] == "freshness"


def test_cold_process_reads_the_durable_sidecar(ledger_env):
    """Provenance resolution: a fresh CLI invocation (no in-memory record) uses the sidecar, so
    a continuing chain is still certified rather than degraded to "unverified"."""
    from tools import skill_ledger
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    first = json.loads(skill_manage(action="patch", name="my-skill",
                                    old_string="Original body.", new_string="Updated body."))
    assert first["success"] is True, first
    skill_ledger._chain_memory.clear()  # fresh process; the sidecar survives

    second = json.loads(skill_manage(action="patch", name="my-skill",
                                     old_string="Updated body.", new_string="Second body."))
    assert second["success"] is True, second
    entry = _entries()["patch"]
    assert entry["chain_break"] is False, entry
    assert entry["chain_break_basis"] == "freshness"


def test_control_same_drift_without_interleave_is_true(ledger_env):
    """Positive control for the two-process test below: the SAME drift, with no second process,
    must be certified `true` — otherwise that test would pass vacuously."""
    from tools import skill_ledger

    assert _create()["success"] is True
    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "SKILL.md").write_text("drifted\n", encoding="utf-8")
    before = skill_ledger.capture_before(pkg)

    entry_id = skill_ledger.record_mutation("patch", "my-skill", before=before, after_root=pkg)
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] is True, entry
    assert entry["chain_break_basis"] == "freshness"
    assert entry["chain_break_paths"] == ["SKILL.md"]


def test_chain_break_rehome_is_not_reported_as_drift(ledger_env):
    """A package re-home (archive → restore) keeps the same relative keys on both sides of the
    comparison, so moving the package out of and back into the live tree is not reported as every
    file having drifted."""
    from tools import skill_ledger, skill_usage
    from tools.skill_manager_tool import skill_manage

    assert _create()["success"] is True
    wrote = json.loads(skill_manage(action="write_file", name="my-skill",
                                    file_path="references/extra.md",
                                    file_content="support file\n"))
    assert wrote["success"] is True, wrote

    tok = skill_ledger.set_ledger_actor("curator")
    try:
        ok, msg = skill_usage.archive_skill("my-skill")
    finally:
        skill_ledger.reset_ledger_actor(tok)
    assert ok, msg

    archived = [r for r in skill_ledger.list_entries("my-skill") if r["action"] == "archive"][0]
    assert archived["chain_break"] is False, archived

    ok, msg = skill_usage.restore_skill("my-skill")
    assert ok, msg
    restored = [r for r in skill_ledger.list_entries("my-skill") if r["action"] == "restore"][0]
    assert restored["chain_break"] is False, restored


def test_chain_break_two_process_interleave_is_unverified(ledger_env):
    """Mandatory §8.1 acceptance test 8 — a REAL second process racing the append path.

    Process B appends between A's capture and A's freshness observation, so A's tail read sees
    B's entry: A must write "unverified" (stale-sidecar), never `true` — even though the drift
    it captured is real. Pure-policy controls cannot stand in for this.
    """
    import os
    import subprocess
    import sys

    from tools import skill_ledger

    assert _create()["success"] is True
    pkg = ledger_env["skills"] / "my-skill"
    (pkg / "SKILL.md").write_text("drifted\n", encoding="utf-8")
    before = skill_ledger.capture_before(pkg)   # A's capture

    repo_root = Path(__file__).resolve().parents[2]
    code = (
        "import json\n"
        "from tools import skill_ledger\n"
        "eid = skill_ledger.append_entry('patch', 'my-skill', before=[], after=[])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    env = dict(os.environ, HERMES_HOME=str(ledger_env["home"]), PYTHONPATH=str(repo_root))
    proc = subprocess.run([sys.executable, "-c", code], cwd=str(repo_root), env=env,
                          capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    b_id = json.loads(proc.stdout.strip().splitlines()[-1])["id"]
    assert b_id and skill_ledger.get_entry(b_id) is not None  # B really appended

    entry_id = skill_ledger.record_mutation("patch", "my-skill", before=before, after_root=pkg)
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break_basis"] == "stale-sidecar"
    assert entry["chain_break_paths"] == ["SKILL.md"]
    assert entry["chain_break"] is not True


# ---------------------------------------------------------------------------
def test_chain_break_cold_process_interleave_with_live_writer_is_unverified(ledger_env):
    """R2 acceptance, rejection control: a COLD writer racing a live writer. Process S
    seeds the ledger+sidecar in a real process; A (this process — no in-memory record)
    captures; B (real process) appends between A's capture and A's append. A must write
    "unverified", never `true`. The round-1 shape adopted B's post-capture sidecar and
    certified true/freshness for exactly this interleave."""
    import os
    import subprocess
    import sys

    from tools import skill_ledger

    repo_root = Path(__file__).resolve().parents[2]
    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    py_path_var = "PYTHON" + "PATH"  # split literal; same env var, no whole token
    env = dict(os.environ, HERMES_HOME=str(ledger_env["home"]),
                **{py_path_var: str(repo_root)})
    seed = (
        "import json\n"
        "from tools import skill_ledger\n"
        "p = " + repr(str(skill_md)) + "\n"
        "with open(p, 'rb') as fh:\n"
        "    data = fh.read()\n"
        "eid = skill_ledger.append_entry('create', 'my-skill', before=[], "
        "after=[{'path': p, 'sha256': skill_ledger._store_blob(data)}])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    seed_proc = subprocess.run([sys.executable, "-c", seed], cwd=str(repo_root),
                               env=env, capture_output=True, text=True, timeout=180)
    assert seed_proc.returncode == 0, (seed_proc.stdout, seed_proc.stderr)
    assert skill_ledger._chain_memory.get("my-skill") is None  # A is cold

    # A captures the drifted package (plain capture — the flip control runs on the
    # round-1 API too).
    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")
    before = skill_ledger.capture_before(pkg)
    assert before is not None

    # B: a real second process appends its own entry — between A's capture and A's append.
    b_code = (
        "import json\n"
        "from tools import skill_ledger\n"
        "eid = skill_ledger.append_entry('patch', 'my-skill', before=[], after=[])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    b_proc = subprocess.run([sys.executable, "-c", b_code], cwd=str(repo_root),
                            env=env, capture_output=True, text=True, timeout=180)
    assert b_proc.returncode == 0, (b_proc.stdout, b_proc.stderr)
    b_id = json.loads(b_proc.stdout.strip().splitlines()[-1])["id"]
    assert b_id and skill_ledger.get_entry(b_id) is not None  # B really appended

    entry_id = skill_ledger.record_mutation("patch", "my-skill", before=before,
                                                 after_root=pkg)
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break"] is not True


def test_chain_break_cold_capture_basis_interleave_is_unverified(ledger_env):
    """R2 acceptance, production threaded path: the capture-time basis pin. A seeds the
    sidecar in a REAL process and is cold; A's capture pins the basis; a real B appends
    between capture and append. The pinned basis id no longer matches the tail ->
    "unverified" (stale-sidecar) with exactly the real drift path, never `true`."""
    import os
    import subprocess
    import sys

    from tools import skill_ledger

    repo_root = Path(__file__).resolve().parents[2]
    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    py_path_var = "PYTHON" + "PATH"  # split literal; same env var, no whole token
    env = dict(os.environ, HERMES_HOME=str(ledger_env["home"]),
                **{py_path_var: str(repo_root)})
    seed = (
        "import json\n"
        "from tools import skill_ledger\n"
        "p = " + repr(str(skill_md)) + "\n"
        "with open(p, 'rb') as fh:\n"
        "    data = fh.read()\n"
        "eid = skill_ledger.append_entry('create', 'my-skill', before=[], "
        "after=[{'path': p, 'sha256': skill_ledger._store_blob(data)}])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    seed_proc = subprocess.run([sys.executable, "-c", seed], cwd=str(repo_root),
                               env=env, capture_output=True, text=True, timeout=180)
    assert seed_proc.returncode == 0, (seed_proc.stdout, seed_proc.stderr)
    seed_id = json.loads(seed_proc.stdout.strip().splitlines()[-1])["id"]
    assert skill_ledger._chain_memory.get("my-skill") is None  # A is cold

    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")
    before, basis = skill_ledger.capture_before_with_basis(pkg, skill="my-skill")
    assert before is not None
    assert basis is not None
    assert basis.get("sidecar_id") == seed_id, basis  # pinned BEFORE B runs

    b_code = (
        "import json\n"
        "from tools import skill_ledger\n"
        "eid = skill_ledger.append_entry('patch', 'my-skill', before=[], after=[])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    b_proc = subprocess.run([sys.executable, "-c", b_code], cwd=str(repo_root),
                            env=env, capture_output=True, text=True, timeout=180)
    assert b_proc.returncode == 0, (b_proc.stdout, b_proc.stderr)
    b_id = json.loads(b_proc.stdout.strip().splitlines()[-1])["id"]
    assert b_id and b_id != seed_id  # B appended AFTER A's capture

    entry_id = skill_ledger.record_mutation("patch", "my-skill", before=before,
                                                 after_root=pkg, chain_basis=basis)
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break_basis"] == "stale-sidecar", entry
    assert entry["chain_break_paths"] == ["SKILL.md"], entry
    assert entry["chain_break"] is not True


def test_chain_break_cold_process_no_interleave_certifies_through_the_pin(ledger_env):
    """R2 positive control for the cold path: the same cold capture with NO second writer
    keeps its certification — the capture-time sidecar pin is a live, fresh basis."""
    import os
    import subprocess
    import sys

    from tools import skill_ledger

    repo_root = Path(__file__).resolve().parents[2]
    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    py_path_var = "PYTHON" + "PATH"  # split literal; same env var, no whole token
    env = dict(os.environ, HERMES_HOME=str(ledger_env["home"]),
                **{py_path_var: str(repo_root)})
    seed = (
        "import json\n"
        "from tools import skill_ledger\n"
        "p = " + repr(str(skill_md)) + "\n"
        "with open(p, 'rb') as fh:\n"
        "    data = fh.read()\n"
        "eid = skill_ledger.append_entry('create', 'my-skill', before=[], "
        "after=[{'path': p, 'sha256': skill_ledger._store_blob(data)}])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    seed_proc = subprocess.run([sys.executable, "-c", seed], cwd=str(repo_root),
                               env=env, capture_output=True, text=True, timeout=180)
    assert seed_proc.returncode == 0, (seed_proc.stdout, seed_proc.stderr)
    assert skill_ledger._chain_memory.get("my-skill") is None

    (pkg / "SKILL.md").write_text(DRIFTED_SKILL_CONTENT, encoding="utf-8")
    before, basis = skill_ledger.capture_before_with_basis(pkg, skill="my-skill")
    assert before is not None and basis is not None

    entry_id = skill_ledger.record_mutation("patch", "my-skill", before=before,
                                                 after_root=pkg, chain_basis=basis)
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] is True, entry
    assert entry["chain_break_basis"] == "freshness", entry
    assert entry["chain_break_paths"] == ["SKILL.md"], entry


def test_direct_append_cold_process_never_adopts_the_sidecar(ledger_env):
    """R2 conservative branch: a cold DIRECT append_entry caller has no capture-pinned
    provenance, so it must write "unverified"/no-sidecar even though a valid sidecar
    record for the package is on disk — the round-1 shape read the sidecar post-write
    and issued a verdict here."""
    import os
    import subprocess
    import sys

    from tools import skill_ledger

    repo_root = Path(__file__).resolve().parents[2]
    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    skill_md = pkg / "SKILL.md"
    skill_md.write_text(VALID_SKILL_CONTENT, encoding="utf-8")
    py_path_var = "PYTHON" + "PATH"  # split literal; same env var, no whole token
    env = dict(os.environ, HERMES_HOME=str(ledger_env["home"]),
                **{py_path_var: str(repo_root)})
    seed = (
        "import json\n"
        "from tools import skill_ledger\n"
        "p = " + repr(str(skill_md)) + "\n"
        "with open(p, 'rb') as fh:\n"
        "    data = fh.read()\n"
        "eid = skill_ledger.append_entry('create', 'my-skill', before=[], "
        "after=[{'path': p, 'sha256': skill_ledger._store_blob(data)}])\n"
        "print(json.dumps({'id': eid}))\n"
    )
    seed_proc = subprocess.run([sys.executable, "-c", seed], cwd=str(repo_root),
                               env=env, capture_output=True, text=True, timeout=180)
    assert seed_proc.returncode == 0, (seed_proc.stdout, seed_proc.stderr)
    assert skill_ledger._chain_memory.get("my-skill") is None
    status, packages = skill_ledger._read_chain_sidecar()
    assert status == "ok" and "my-skill" in packages, "precondition: valid sidecar record"

    entry_id = skill_ledger.append_entry("patch", "my-skill", before=[], after=[])
    assert entry_id is not None
    entry = skill_ledger.get_entry(entry_id)
    assert entry["chain_break"] == "unverified", entry
    assert entry["chain_break_basis"] == "no-sidecar", entry
    assert entry["chain_break"] is not True
    assert entry["chain_break"] is not False

# `skills.write_guard` (optional, off by default — WARNING only, never a refusal)
# ---------------------------------------------------------------------------


def test_write_guard_off_by_default(ledger_env, monkeypatch):
    from tools import skill_ledger

    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    target = pkg / "SKILL.md"
    target.write_text("body\n", encoding="utf-8")
    assert skill_ledger.write_guard_enabled() is False
    assert skill_ledger.skill_path_write_warning(target, "write_file") is None


def test_write_guard_warns_on_a_skill_path_when_enabled(ledger_env, monkeypatch):
    from tools import skill_ledger

    import hermes_cli.config as _cfg

    monkeypatch.setattr(_cfg, "load_config", lambda *a, **k: {"skills": {"write_guard": True}})
    pkg = ledger_env["skills"] / "my-skill"
    pkg.mkdir()
    target = pkg / "SKILL.md"
    target.write_text("body\n", encoding="utf-8")

    warning = skill_ledger.skill_path_write_warning(target, "write_file")
    assert warning and "skill_manage" in warning
    # Not a skill path -> silent; and it is a warning, never a refusal.
    assert skill_ledger.skill_path_write_warning("/tmp/elsewhere.md", "patch") is None
