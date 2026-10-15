"""Cross-implementation conformance: the fixtures under tests/conformance/.

Two halves. The first runs the Python verifier against every committed fixture
and checks it still says what expected.json records, and that the fixtures are
what scripts/gen_conformance.py produces today. The second, when a Go
toolchain is on PATH, builds the independent verifier in verifiers/go and
checks it reaches the same verdict with the same exit code on every fixture,
and the same bytes on every canonical case. Nothing here touches the network:
the Go module has no dependencies to fetch and the build runs with GOPROXY=off.
"""
from __future__ import annotations

import contextlib
import filecmp
import io
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aileron import cli
from aileron.chainlog import verify
from aileron.events import canonical_json
from aileron.signing import verify_checkpoint

ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE = ROOT / "tests" / "conformance"
CASES = sorted(p for p in (CONFORMANCE / "cases").iterdir() if p.is_dir())
CASE_IDS = [p.name for p in CASES]
GO_MODULE = ROOT / "verifiers" / "go"
LOG = "journal.jsonl"

# Exception text embedded in these messages comes from the Python runtime and
# differs between versions (3.13 appends the offending value to the NaN
# message, for example). Everything before the marker is compared exactly.
_RUNTIME_TEXT = re.compile(r"(invalid JSON: |invalid UTF-8: |uncanonicalizable content: ).*")


def normalize(errors: list[str]) -> list[str]:
    return [_RUNTIME_TEXT.sub(r"\1", e) for e in errors]


def run_cli(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue() + err.getvalue()


def load_expected(case: Path) -> dict:
    return json.loads((case / "expected.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- Python half


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_python_verify_matches_expected(case, monkeypatch):
    expected = load_expected(case)["verify"]
    monkeypatch.chdir(case)
    result = verify(LOG)
    assert result.ok == expected["ok"]
    assert result.count == expected["count"]
    assert result.first_bad_seq == expected["first_bad_seq"]
    assert normalize(result.errors) == normalize(expected["errors"])
    code, output = run_cli(["verify", LOG])
    assert code == expected["exit_code"]
    assert expected["verdict"] in output.splitlines()


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_python_verify_checkpoint_matches_expected(case, monkeypatch):
    expected = load_expected(case)["checkpoint"]
    monkeypatch.chdir(case)
    assert verify_checkpoint(LOG, expected["key"]) is expected["valid"]
    code, output = run_cli(["verify-checkpoint", LOG, "--key", expected["key"]])
    assert code == expected["exit_code"]
    assert expected["verdict"] in output.splitlines()


def canonical_case_ids():
    cases = json.loads((CONFORMANCE / "canonical_cases.json").read_text(encoding="utf-8"))
    return cases, [c["name"] for c in cases]


_CANONICAL_CASES, _CANONICAL_IDS = canonical_case_ids()


@pytest.mark.parametrize("case", _CANONICAL_CASES, ids=_CANONICAL_IDS)
def test_python_canonical_cases(case):
    if "error" in case:
        with pytest.raises(ValueError):
            canonical_json(json.loads(case["source"]))
        return
    assert canonical_json(json.loads(case["source"])) == case["canonical"]


def test_fixtures_are_what_the_generator_produces(tmp_path):
    """The committed fixtures must match the current library, or they are
    documenting behaviour that no longer exists."""
    out = tmp_path / "conformance"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_conformance.py"), "--out", str(out)],
        capture_output=True, text=True, cwd=str(ROOT), check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert sorted(p.name for p in (out / "cases").iterdir()) == CASE_IDS
    for case in CASES:
        fresh = out / "cases" / case.name
        committed_files = sorted(p.name for p in case.iterdir())
        assert sorted(p.name for p in fresh.iterdir()) == committed_files, case.name
        for name in committed_files:
            if name == "expected.json":
                a = json.loads((case / name).read_text(encoding="utf-8"))
                b = json.loads((fresh / name).read_text(encoding="utf-8"))
                a["verify"]["errors"] = normalize(a["verify"]["errors"])
                b["verify"]["errors"] = normalize(b["verify"]["errors"])
                assert a == b, f"{case.name}/expected.json differs; rerun scripts/gen_conformance.py"
            else:
                assert filecmp.cmp(case / name, fresh / name, shallow=False), (
                    f"{case.name}/{name} differs; rerun scripts/gen_conformance.py")
    assert filecmp.cmp(CONFORMANCE / "canonical_cases.json", out / "canonical_cases.json",
                       shallow=False), "canonical_cases.json differs; rerun scripts/gen_conformance.py"


# -------------------------------------------------------------------- Go half


def _go_toolchain() -> tuple[str, str] | None:
    """(go binary, reason it cannot be used) with one of the two None."""
    go = shutil.which("go")
    if go is None:
        return None
    try:
        version = subprocess.run([go, "version"], capture_output=True, text=True,
                                 check=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"go(\d+)\.(\d+)", version)
    if match and (int(match.group(1)), int(match.group(2))) < (1, 22):
        return None
    return go, version.strip()


@pytest.fixture(scope="module")
def go_binary(tmp_path_factory):
    toolchain = _go_toolchain()
    if toolchain is None:
        pytest.skip("Go 1.22 or newer is not on PATH; the Go half of the conformance "
                    "suite needs it to build verifiers/go")
    go, _version = toolchain
    binary = tmp_path_factory.mktemp("go-verifier") / "aileron-verify"
    env = dict(os.environ)
    # The module has no dependencies, so nothing needs fetching. These make
    # that a hard guarantee rather than a happy accident.
    env.update({"GOPROXY": "off", "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local",
                "CGO_ENABLED": "0"})
    build = subprocess.run([go, "build", "-o", str(binary), "./cmd/aileron-verify"],
                           cwd=str(GO_MODULE), env=env, capture_output=True, text=True,
                           check=False, timeout=600)
    assert build.returncode == 0, f"go build failed:\n{build.stdout}\n{build.stderr}"
    return binary


def run_go(binary: Path, argv: list[str], cwd: Path, stdin: bytes | None = None):
    return subprocess.run([str(binary), *argv], cwd=str(cwd), input=stdin,
                          capture_output=True, check=False, timeout=120)


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_go_verify_agrees(go_binary, case):
    expected = load_expected(case)["verify"]
    completed = run_go(go_binary, ["verify", LOG], case)
    output = (completed.stdout + completed.stderr).decode("utf-8")
    assert completed.returncode == expected["exit_code"], output
    assert expected["verdict"] in output.splitlines(), output
    # The verifier's own error list, one line each, prefixed "error: ".
    got_errors = [line[len("error: "):] for line in output.splitlines()
                  if line.startswith("error: ")]
    if not expected["ok"]:
        assert normalize(got_errors) == normalize(expected["errors"])


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_go_verify_checkpoint_agrees(go_binary, case):
    expected = load_expected(case)["checkpoint"]
    completed = run_go(go_binary, ["verify-checkpoint", LOG, "--key", expected["key"]], case)
    output = (completed.stdout + completed.stderr).decode("utf-8")
    assert completed.returncode == expected["exit_code"], output
    assert expected["verdict"] in output.splitlines(), output


def test_go_canonical_bytes_agree(go_binary, tmp_path):
    """Every canonical case through the Go binary, compared byte for byte."""
    mismatches = []
    for case in _CANONICAL_CASES:
        source = case["source"].encode("utf-8", "surrogatepass")
        completed = run_go(go_binary, ["canonical"], tmp_path, stdin=source)
        if "error" in case:
            if completed.returncode == 0:
                mismatches.append((case["name"], "accepted", completed.stdout))
            continue
        if completed.returncode != 0:
            mismatches.append((case["name"], "refused", completed.stderr))
            continue
        want = case["canonical"].encode("ascii") + b"\n"
        if completed.stdout != want:
            mismatches.append((case["name"], completed.stdout, want))
    assert not mismatches, mismatches
