#requires -Version 5.1
<#
.SYNOPSIS
Optional menu-driven terminal interface for PIM profiles. No extra modules required.
.DESCRIPTION
Uses the existing profile/export engines. Preview is read-only; Apply always previews first and
requires the exact target account confirmation. Graph sign-in is off unless explicitly enabled.
Existing command-line entry points remain available.
#>
param([string]$OutDir,[bool]$ConnectGraph=$false)
$ErrorActionPreference='Stop'
if(-not [Environment]::UserInteractive){throw 'The TUI requires an interactive terminal. Use the normal CLI parameters for automation.'}
$Apply=$false;$Interactive=$false
. (Join-Path $PSScriptRoot 'lib/CadmAccess.Core.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmProfile.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmTui.ps1')
if(-not $OutDir){$OutDir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PIM-Automation/tui'}
Start-CadmTuiLoop -Root $PSScriptRoot -OutDir $OutDir -ConnectGraph $ConnectGraph

exit 0
