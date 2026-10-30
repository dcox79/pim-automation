"""Run the real profile launcher with mocked cloud boundaries and real audit persistence."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_workflow_entrypoint import CORE, PROFILE

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
@pytest.mark.parametrize("scenario,code,state", [
    ("success", 0, "Verified"),
    ("confirm-exact", 0, "Verified"),
    ("confirm-wrong", 0, "Cancelled"),
    ("confirm-bare", 0, "Cancelled"),
    ("cancel", 0, "Cancelled"),
    ("stale", 2, "Refused"),
    ("pending", 1, "PendingOrUnknown"),
    ("read-error", 1, "PendingOrUnknown"),
    ("partial", 1, "Partial"),
    ("preview", 0, "Preview"),
    ("blocked", 2, "Refused"),
    ("blocked-preview", 2, "Preview"),
])
def test_profile_launcher_journals_final_outcome(tmp_path, shell, scenario, code, state):
    script = tmp_path / "Invoke-CadmAccess.ps1"
    shutil.copyfile(ROOT / "scripts/cadm/Invoke-CadmAccess.ps1", script)
    lib = tmp_path / "lib"
    lib.mkdir()
    core = CORE + """
function Write-Section {param($Name)}
function Read-Host {param($Prompt) if($env:WORKFLOW_SCENARIO -eq 'cancel'){'cancel'}elseif($env:WORKFLOW_SCENARIO -eq 'confirm-exact'){'APPLY person-cadm@example.com'}elseif($env:WORKFLOW_SCENARIO -eq 'confirm-wrong'){'APPLY other@example.com'}else{'APPLY'}}
"""
    (lib / "CadmAccess.Core.ps1").write_text(core)
    (lib / "CadmProfile.ps1").write_text(PROFILE + "\n. (Join-Path $PSScriptRoot 'CadmAudit.ps1')\n. (Join-Path $PSScriptRoot 'CadmActivation.ps1')\n. (Join-Path $PSScriptRoot 'CadmBackup.ps1')\n")
    (lib / "CadmExport.ps1").write_text("")
    (lib / "tenant.psd1").write_text("@{}")
    (lib / "test.psd1").write_text("@{}")
    shutil.copyfile(ROOT / "scripts/cadm/lib/CadmAudit.ps1", lib / "CadmAudit.ps1")
    for name in ("CadmActivation.ps1", "CadmBackup.ps1"):
        shutil.copyfile(ROOT / "scripts/cadm/lib" / name, lib / name)
    output = tmp_path / "evidence"
    command = [shell, "-NoProfile", "-File", str(script), "-Mode", "profile",
               "-ProfileName", "test", "-TargetUser", "person-cadm@example.com",
               "-OutDir", str(output), "-VerificationAttempts", "1", "-VerificationDelaySeconds", "0"]
    if scenario not in ("preview", "blocked-preview"):
        command += ["-Apply"]
    if scenario.startswith("confirm-"):
        command += ["-ConfirmTarget"]
    result = subprocess.run(command, env=dict(os.environ, WORKFLOW_SCENARIO=scenario),
                            text=True, capture_output=True, timeout=90)
    assert result.returncode == code, result.stdout + result.stderr
    review = json.loads(next(output.rglob("review.json")).read_text(encoding="utf-8-sig"))
    assert review["State"] == state
    manifest = json.loads((Path(review["BackupPath"]) / "manifest.json").read_text(encoding="utf-8-sig"))
    assert manifest["State"] == "Complete"
    assert len(manifest["Files"]) == 2
    if state in ("Preview", "Cancelled", "Refused"):
        assert not list(output.rglob("submissions.json"))
    else:
        outcome = json.loads(next(output.rglob("outcome.json")).read_text(encoding="utf-8-sig"))
        assert outcome["State"] == state
        assert outcome["Context"]["Actor"] == "operator@example.com"
        assert outcome["Context"]["TemplateHash"]
        if state == "Verified":
            assert outcome["Verification"][0]["Evidence"][0]["TermMatches"] is True
