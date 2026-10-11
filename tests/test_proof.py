import json, pathlib, subprocess, sys
import pytest

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import mcp_scan, evaluate

SCAN = [sys.executable, str(ROOT / "mcp_scan.py")]


def run(*args):
    return subprocess.run(SCAN + [str(a) for a in args], capture_output=True, text=True)


def test_readme_matches_output():
    readme = (ROOT / "README.md").read_text()
    assert evaluate.results() in readme, "README results drifted from evaluate.py"


def test_every_fixture_has_expectation_and_back():
    on_disk = {p.name for p in (ROOT / "fixtures").glob("*.json")}
    assert len(on_disk) >= 12
    assert on_disk == set(evaluate.EXPECTED)


def test_all_fixtures_match_expectation():
    assert evaluate.main() == 0


@pytest.mark.parametrize("rule_id", sorted(r for r, _ in mcp_scan.RULES))
def test_mutant_removing_rule_changes_result(rule_id, monkeypatch):
    real = evaluate.results()
    monkeypatch.setattr(mcp_scan, "RULES", [(r, f) for r, f in mcp_scan.RULES if r != rule_id])
    assert evaluate.results() != real, f"disabling {rule_id} changed nothing"


def test_high_finding_exits_1():
    assert run(ROOT / "fixtures" / "bad_01_shell_tool.json").returncode == 1


def test_medium_only_exits_0():
    assert run(ROOT / "fixtures" / "bad_03_fs_schema_unconstrained.json").returncode == 0


def test_clean_exits_0():
    assert run(ROOT / "fixtures" / "clean_01_scoped_fs.json").returncode == 0


def test_missing_file_exits_2(tmp_path):
    assert run(tmp_path / "nope.json").returncode == 2


def test_bad_json_exits_2(tmp_path):
    p = tmp_path / "x.json"; p.write_text("{not json")
    assert run(p).returncode == 2


def test_wrong_shape_exits_2(tmp_path):
    p = tmp_path / "x.json"; p.write_text(json.dumps({"name": "s", "tools": "oops"}))
    assert run(p).returncode == 2


def test_empty_dir_exits_2(tmp_path):
    assert run(tmp_path).returncode == 2


def test_no_args_exits_2():
    assert run().returncode == 2


def test_unreadable_beats_clean(tmp_path):
    p = tmp_path / "x.json"; p.write_text("[")
    assert run(ROOT / "fixtures" / "clean_01_scoped_fs.json", p).returncode == 2
