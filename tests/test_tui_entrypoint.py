"""Exercise real TUI script boundaries without cloud calls."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
def test_tui_child_exit_returns_to_menu(tmp_path, shell):
    shutil.copyfile(ROOT / "scripts/cadm/lib/CadmTui.ps1", tmp_path / "CadmTui.ps1")
    (tmp_path / "child.ps1").write_text("param([string]$Value)\nif($Value -ne 'literal;$value'){throw 'Argument changed'}\nexit 2\n")
    (tmp_path / "run.ps1").write_text("""
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'CadmTui.ps1')
$script:TuiRoot=$PSScriptRoot
$code=Invoke-CadmTuiCommand 'child.ps1' @{Value='literal;$value'}
if($code -ne 2){throw "Lost exit code: $code"}
function Read-Host {param($Prompt) 'b'}
function Initialize-AzInvoker {throw 'Must stay offline'}
Start-CadmTuiLoop -Root $PSScriptRoot -OutDir $PSScriptRoot
Write-Host 'RETURNED-TO-CALLER'
""")
    result = subprocess.run([shell, "-NoProfile", "-File", str(tmp_path / "run.ps1")],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exit 2" in result.stdout
    assert "Menu closed." in result.stdout
    assert "RETURNED-TO-CALLER" in result.stdout


@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
@pytest.mark.parametrize("mixed", [False, True])
def test_launcher_tui_route_is_offline_and_rejects_mixed_modes(tmp_path, shell, mixed):
    launcher = tmp_path / "Invoke-CadmAccess.ps1"
    shutil.copyfile(ROOT / "scripts/cadm/Invoke-CadmAccess.ps1", launcher)
    (tmp_path / "Start-CadmTui.ps1").write_text("""
param([bool]$ConnectGraph,[string]$OutDir)
if($ConnectGraph){throw 'Unexpected Graph sign-in'}
Write-Host 'MENU-ROUTED'
exit 0
""")
    command = [shell, "-NoProfile", "-File", str(launcher), "-Tui"]
    if mixed:
        command += ["-Apply"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if mixed:
        assert result.returncode != 0
        assert "MENU-ROUTED" not in result.stdout
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "MENU-ROUTED" in result.stdout


@pytest.mark.parametrize("shell", ["pwsh", "powershell"])
@pytest.mark.parametrize("answers", ["b\n", "8\nb\nb\n"])
def test_real_tui_quit_without_login(shell, answers):
    result = subprocess.run(
        [shell, "-NoProfile", "-File", str(ROOT / "scripts/cadm/Invoke-CadmAccess.ps1"), "-Tui"],
        input=answers, capture_output=True, text=True, timeout=30,
    )
    if "requires an interactive terminal" in result.stderr:
        pytest.skip("Host has no interactive terminal")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PIM ACCESS" in result.stdout
    assert "Menu closed." in result.stdout

