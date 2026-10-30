#requires -Version 5.1
<#
.SYNOPSIS
Save verified, dated local copies of one tenant's configuration and profiles. No cloud access.
.EXAMPLE
.\scripts\cadm\Backup-CadmProfiles.ps1 -TenantName odyssey
#>
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$')][string]$TenantName)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/CadmAudit.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmBackup.ps1')
$tenantDirectory=Join-Path (Join-Path $PSScriptRoot 'tenants') $TenantName
$path=Join-Path $tenantDirectory 'tenant.psd1'
$tenant=Import-PowerShellDataFile -LiteralPath $path
$tenant.Path=$path;$tenant.ProfilesDir=Join-Path $tenantDirectory 'profiles'
$profiles=@(Get-ChildItem -LiteralPath $tenant.ProfilesDir -Filter '*.psd1' -File | Select-Object -ExpandProperty FullName)
$backup=Backup-CadmProfileFiles -Tenant $tenant -ProfilePaths $profiles -Reason 'Manual tenant/profile backup'
Write-Host "Backed up $($profiles.Count) profile(s) and tenant configuration to $($backup.Path)"
Write-Host 'Local recovery copy only: anyone with access to this folder can edit or delete it. Restoring a file does not change Azure permissions.'
