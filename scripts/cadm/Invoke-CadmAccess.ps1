#requires -Version 5.1

<#
.SYNOPSIS
  One entry point for CADM account provisioning: clone an existing user's access, clone it
  interactively, or apply a profile template. Dry-run by default; -Apply performs the grants.

.DESCRIPTION
  Run it with no arguments for a menu. Every option is also fully parameter-driven, so the same
  script automates.

  ---------------------------------------------------------------------------------------
  QUICK START
  ---------------------------------------------------------------------------------------
      .\scripts\cadm\Invoke-CadmAccess.ps1

  Needs a current `az login` and the Microsoft.Graph.Authentication module
  (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser - no admin needed).

  FOUR MODES

    1. Clone (automatic)     - read everything a source user holds, diff, grant the gap.
                               Delegates to Copy-CadmAccess.ps1.
    2. Clone (interactive)   - same, but prints every duplicable grant as a numbered row and
                               grants only the ones you pick.
    3. Apply a profile       - grant a named template. No source user; the template is the
                               intent.
    4. Export eligibility    - read a source user and save a tenant-local profile; no cloud writes.

  WHICH TO USE

  Prefer a PROFILE for a new account. Cloning copies whatever the source actually has, which
  includes its drift. A profile encodes the intended posture; a clone reflects the source's
  current assignments. Review the safety findings in handoff/project-review.md before applying.

  Clone when you are deliberately mirroring a peer (a like-for-like replacement), or auditing
  what a template account would propagate.

  ---------------------------------------------------------------------------------------
  TENANT BINDING - read this before using it in another tenant
  ---------------------------------------------------------------------------------------
  Everything tenant-specific lives OUTSIDE this script, under scripts/cadm/tenants/<name>/:

      tenant.psd1          tenantId, root management group, scope shorthands, defaults
      profiles/*.psd1      one file per profile template

  The launcher reads the CURRENT az login's tenantId and matches it against those files. No
  match, no run - it refuses before reading anything else. That is what makes this safe to carry
  between customers: profiles written for one tenant cannot be applied inside another's.

  To onboard a new tenant, copy the folder, change TenantId / RootManagementGroupId /
  ScopeTokens, and edit the profiles. No script changes.

  ---------------------------------------------------------------------------------------
  PROFILE FORMAT
  ---------------------------------------------------------------------------------------
  PSD1 (PowerShell data) - it takes comments, parses natively on 5.1 and 7.x, and is data-only,
  so a tampered file cannot execute code.

      @{
          Name        = 'Azure Owner (JIT)'
          Description = 'Standing Reader at the root MG; Owner only via PIM activation'
          Rbac                  = @( @{ Role = 'Reader'; Scope = 'root-mg' } )
          GroupMemberships      = @()
          PimGroupEligibilities = @( @{ Group = 'EXAMPLE_PIM_Azure_Owner_Role'; AccessId = 'member' } )
          DirectoryRoleEligibilities = @()
      }

  Scope is either a ScopeTokens key from tenant.psd1 or a full /subscriptions/... or
  /providers/... resource id.

  FIVE PLANES a profile can grant:
    PimResourceEligibilities   Azure-resource PIM eligibility (role-definition GUID + scope)
    Rbac                       standing Azure RBAC at a scope
    GroupMemberships           standing membership of a plain cloud group
    PimGroupEligibilities      PIM for GROUPS - eligible to activate a group's membership
    DirectoryRoleEligibilities standard PIM - eligible to activate an Entra DIRECTORY role

  The last two are different products with different APIs, different scope families and
  SEPARATE CONSENT. A tenant set up for PIM for Groups is not automatically consented for
  directory-role PIM (RoleEligibilitySchedule.ReadWrite.Directory vs *.AzureADGroup); the
  launcher requests the extra scopes only when a profile actually uses that plane.

  Exported eligibilities preserve expiry by default. New Azure-resource profiles validate their
  bounded term against the target policy before applying. Existing group/directory profiles keep
  their legacy duration behavior; see the runbook for remaining limitations.

  WHAT A PROFILE MAY NOT SAY. The engine refuses these regardless of what the file contains, so
  the policy lives in one place instead of depending on template authors remembering it:

    * standing Owner, User Access Administrator, or RBAC Administrator - grant just-in-time via
      an eligibility instead
    * root scope '/'
    * permanent membership of a PIM-managed or role-assignable group - that is the escalation
      this whole toolchain exists to prevent
    * on-prem synced groups - they are mastered in AD and Graph rejects the write
    * a STANDING directory role. There is no key for one; this plane only ever makes someone
      eligible. Global Administrator is therefore permitted, but exclusively as a JIT
      eligibility - which is Microsoft's recommended pattern for the role.

  Re-applying is safe: anything already in place is reported SKIP-EXISTS.

  ---------------------------------------------------------------------------------------
  LAYOUT
  ---------------------------------------------------------------------------------------
      scripts/Copy-CadmAccess.ps1          clone entry point (standalone CLI, unchanged)
      scripts/cadm/Invoke-CadmAccess.ps1   this launcher
      scripts/cadm/lib/CadmAccess.Core.ps1 shared engine (az/Graph plumbing, discovery)
      scripts/cadm/lib/CadmProfile.ps1     tenant binding, profile load/validate/apply
      scripts/cadm/tenants/<name>/...      per-tenant config and profiles

  The folder is the unit of handoff, not any single file. Every entry point prints its own
  version plus the core version, so a mismatched copy is visible at a glance.

  Exit codes: 0 = success (or dry run), 1 = at least one grant failed, 2 = refused to apply.

.PARAMETER Tui          Open the optional persistent terminal menu. Graph sign-in defaults off.
.PARAMETER ConfirmTarget Require APPLY plus the exact target UPN at confirmation (used by the TUI).
.PARAMETER Mode         clone | interactive | profile | export. Omit for the menu.
.PARAMETER SourceUser   Source account for clone or export modes. UPN, objectId, or UPN prefix.
.PARAMETER TargetUser   Account to grant. Same accepted forms.
.PARAMETER ProfileName  Profile key for -Mode profile or export - the psd1 file's basename
                        (e.g. 'azure-owner-jit'). Named ProfileName because $Profile is an
                        automatic PowerShell variable and would collide.
.PARAMETER ExportPlanes AzureResource (default), Group, DirectoryRole. Only selected planes are read.
.PARAMETER EligibilityDuration Optional positive ISO-8601 duration for exported entries. Omit to
                        preserve source expiry; permanent source eligibility uses the bounded tenant default.
.PARAMETER AdditionalScopes Extra ARM scopes or tenant scope tokens to read during export.
.PARAMETER IncludeManagementGroups Discover and query accessible management groups during export.
.PARAMETER IncludeGroupDerivedAccess Record group-derived access as evidence; never convert it to direct grants. Requires Graph read access.
.PARAMETER VerificationAttempts Bounded post-apply read-back attempts (default 3).
.PARAMETER VerificationDelaySeconds Delay between read-back attempts (default 5).
.PARAMETER ListProfiles Print the available profiles for the bound tenant and exit.
.PARAMETER Apply        Perform the grants. Omit for a dry run (the default).
.PARAMETER Force        With -Apply, skip the typed confirmation.
.PARAMETER ConnectGraph Auto-connect Graph PowerShell when no usable session exists. Default
                        $true. Pass -ConnectGraph:$false for unattended runs.
.PARAMETER UseDeviceCode Sign in with a device code instead of a browser window.
.PARAMETER OutDir       Audit output directory. Defaults to
                        %LOCALAPPDATA%\PIM-Automation\cadm-clone\<date>\ - deliberately outside the
                        repo, so a checkout cannot discard the record of a privileged grant.
.PARAMETER Justification Text stamped into PIM requests. Defaults to the tenant's
                        JustificationPrefix.
.PARAMETER TicketNumber Optional ticket reference recorded on PIM requests.
.PARAMETER TicketSystem Optional ticket system name recorded on PIM requests.

.EXAMPLE
  .\scripts\cadm\Invoke-CadmAccess.ps1
  Menu.

.EXAMPLE
  .\scripts\cadm\Invoke-CadmAccess.ps1 -ListProfiles

.EXAMPLE
  .\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName azure-owner-jit -TargetUser target-admin
  Dry run of a profile apply.

.EXAMPLE
  .\scripts\cadm\Invoke-CadmAccess.ps1 -Mode profile -ProfileName azure-owner-jit -TargetUser target-admin -Apply

.EXAMPLE
  .\scripts\cadm\Invoke-CadmAccess.ps1 -Mode interactive -SourceUser source-admin -TargetUser newadmin-cadm
#>

param(
    [switch]$Tui,
    [switch]$ConfirmTarget,
    [ValidateSet('clone', 'interactive', 'profile', 'export')]
    [string]$Mode,
    [string]$SourceUser,
    [string]$TargetUser,
    [string]$ProfileName,
    [switch]$ListProfiles,
    [ValidateSet('AzureResource', 'Group', 'DirectoryRole')]
    [string[]]$ExportPlanes = @('AzureResource'),
    [string]$EligibilityDuration,
    [string[]]$AdditionalScopes,
    [switch]$IncludeManagementGroups,
    [switch]$IncludeGroupDerivedAccess,
    [ValidateRange(1,10)][int]$VerificationAttempts=3,
    [ValidateRange(0,30)][int]$VerificationDelaySeconds=5,
    [switch]$Apply,
    [switch]$Force,
    [bool]$ConnectGraph = $true,
    [switch]$UseDeviceCode,
    [string]$OutDir,
    [string]$Justification,
    [string]$TicketNumber,
    [string]$TicketSystem
)

$ErrorActionPreference = 'Stop'
if($Tui){
    foreach($key in $PSBoundParameters.Keys){
        if($key -notin @('Tui','OutDir','ConnectGraph')){throw '-Tui accepts only OutDir and ConnectGraph; select the operation in the menu.'}
    }
    $tuiParameters=@{ConnectGraph=$false}
    if($OutDir){$tuiParameters.OutDir=$OutDir}
    if($PSBoundParameters.ContainsKey('ConnectGraph')){$tuiParameters.ConnectGraph=$ConnectGraph}
    & (Join-Path $PSScriptRoot 'Start-CadmTui.ps1') @tuiParameters
    exit $LASTEXITCODE
}
$LauncherVersion = '1.7.0 (2026-10-29)'
$Interactive = $false
if ($Mode -eq 'export' -and ($Apply -or $Force -or $TargetUser)) { throw 'Export reads eligibility and writes a local profile only; do not supply Apply, Force, or TargetUser.' }

. (Join-Path $PSScriptRoot 'lib\CadmAccess.Core.ps1')
. (Join-Path $PSScriptRoot 'lib\CadmProfile.ps1')
. (Join-Path $PSScriptRoot 'lib\CadmExport.ps1')

Write-Host "Invoke-CadmAccess v$LauncherVersion (core v$CadmCoreVersion, profile v$CadmProfileVersion)"

Initialize-AzInvoker
$tenant = Import-CadmTenant -TenantsDir (Join-Path $PSScriptRoot 'tenants')
Write-Host "  tenant: $($tenant.Name) [$($tenant.TenantId)]"
Write-Host "  config: $($tenant.Path)"

$profiles = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)

if ($ListProfiles) {
    Write-Section "PROFILES ($($profiles.Count))"
    foreach ($p in $profiles) {
        Write-Host ("  {0,-22} {1}" -f $p.Key, $p.Name)
        if ($p.Description) { Write-Host ("  {0,-22} {1}" -f '', $p.Description) }
    }
    Write-Host ''
    exit 0
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
# Only when the mode was not given. Every prompt below has a parameter equivalent, so nothing
# here is required to automate the tool - the menu is a convenience, not the interface.
if (-not $Mode) {
    if (-not [Environment]::UserInteractive) {
        throw 'no -Mode given and this host is not interactive. Pass -Mode clone|interactive|profile.'
    }
    Write-Section 'CADM ACCESS'
    Write-Host '  [1] Clone a user access automatically   (reads a source user, grants the gap)'
    Write-Host '  [2] Clone interactively                 (pick which rows to grant)'
    Write-Host '  [3] Apply a profile template            (recommended for a new account)'
    Write-Host '  [4] List profiles'
    Write-Host '  [5] Export user PIM eligibility to a profile'
    Write-Host '  [q] Quit'
    Write-Host ''
    while (-not $Mode) {
        switch ((Read-Host 'Choose').Trim()) {
            '1' { $Mode = 'clone' }
            '2' { $Mode = 'interactive' }
            '3' { $Mode = 'profile' }
            '4' {
                Write-Section "PROFILES ($($profiles.Count))"
                foreach ($p in $profiles) {
                    Write-Host ("  {0,-22} {1}" -f $p.Key, $p.Name)
                    if ($p.Description) { Write-Host ("  {0,-22} {1}" -f '', $p.Description) }
                }
                Write-Host ''
            }
            '5' { $Mode = 'export' }
            'q' { Write-Host 'Nothing done.'; exit 0 }
            default { Write-Host '  Enter 1, 2, 3, 4, 5 or q.' }
        }
    }
}

if ($Mode -eq 'export') {
    if ($Apply -or $Force -or $TargetUser) { throw 'Export does not accept Apply, Force, or TargetUser.' }
    if (-not $SourceUser -and [Environment]::UserInteractive) { $SourceUser = (Read-Host 'Source account UPN or object ID').Trim() }
    if (-not $ProfileName -and [Environment]::UserInteractive) { $ProfileName = (Read-Host 'New profile filename key (for example azure-owner-jit)').Trim() }
    if (-not $SourceUser -or -not $ProfileName) { throw 'Export requires -SourceUser and -ProfileName; no target account is needed.' }
    $source = Resolve-CadmUser -Ref $SourceUser
    Write-Host "  source: $($source.displayName) <$($source.userPrincipalName)> $($source.id)"
    Write-Host "  export planes: $($ExportPlanes -join ', ')"
    if ($IncludeGroupDerivedAccess -or $ExportPlanes -contains 'Group' -or $ExportPlanes -contains 'DirectoryRole') {
        Connect-CadmExportGraph -Planes $ExportPlanes -IncludeGroupDerivedAccess:$IncludeGroupDerivedAccess
    }
    $exported = Export-CadmEligibilityProfile -Source $source -Tenant $tenant -ProfileName $ProfileName -Planes $ExportPlanes -Duration $EligibilityDuration -AdditionalScopes $AdditionalScopes -IncludeManagementGroups:$IncludeManagementGroups -IncludeGroupDerivedAccess:$IncludeGroupDerivedAccess
    if(-not $exported.Path){Write-Host "[OK] No direct eligibilities found. Group coverage report: $($exported.CoveragePath). No grant template created.";exit 0}
    $backup=Backup-CadmProfileFiles -Tenant $tenant -ProfilePaths @($exported.Path) -Reason 'Profile export'
    Write-Host "[OK] Profile written to $($exported.Path). Local backup: $($backup.Path)"
    Write-Host "  Azure-resource: $($exported.AzureResource); groups: $($exported.Group); directory roles: $($exported.DirectoryRole)"
    Write-Host '  Discovery scopes and optional group-derived evidence are recorded under Export in the profile.'
    Write-Host '  No access granted. Review the profile, then preview it with -Mode profile and a target user.'
    exit 0
}

if (-not $TargetUser) {
    if (-not [Environment]::UserInteractive) { throw '-TargetUser is required.' }
    $TargetUser = (Read-Host 'Target user (the account to grant)').Trim()
    if (-not $TargetUser) { Write-Host 'No target given - nothing done.'; exit 0 }
}

# ---------------------------------------------------------------------------
# Clone modes - delegate to the field-tested script
# ---------------------------------------------------------------------------
# Copy-CadmAccess.ps1 keeps its own CLI contract and its pinned test suite. Re-implementing the
# clone flow here would fork the escalation guards (SKIP-PIM-ACTIVATED, BLOCKED-PIM-ACTIVE,
# EXCLUDED-ROOT) into a second, untested copy - exactly the failure mode this refactor exists to
# avoid. The launcher adds the menu and the tenant guard, then hands off.
if ($Mode -in @('clone', 'interactive')) {
    if (-not $SourceUser) {
        if (-not [Environment]::UserInteractive) { throw '-SourceUser is required for the clone modes.' }
        $SourceUser = (Read-Host 'Source user (the template account to copy from)').Trim()
        if (-not $SourceUser) { Write-Host 'No source given - nothing done.'; exit 0 }
    }
    $clone = Join-Path (Split-Path $PSScriptRoot -Parent) 'Copy-CadmAccess.ps1'
    if (-not (Test-Path $clone)) { throw "clone script not found at $clone" }

    $splat = @{ TenantId = $tenant.TenantId; SourceUser = $SourceUser; TargetUser = $TargetUser; ConnectGraph = $ConnectGraph }
    if ($Mode -eq 'interactive') { $splat.Interactive = $true }
    elseif ($Apply)              { $splat.Apply = $true }
    if ($Force)         { $splat.Force = $true }
    if ($UseDeviceCode) { $splat.UseDeviceCode = $true }
    if ($OutDir)        { $splat.OutDir = $OutDir }
    if ($Justification) { $splat.Justification = $Justification }
    if ($TicketNumber)  { $splat.TicketNumber = $TicketNumber }
    if ($TicketSystem)  { $splat.TicketSystem = $TicketSystem }

    Write-Host ''
    & $clone @splat
    exit $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Profile mode
# ---------------------------------------------------------------------------
if (-not $ProfileName) {
    if (-not [Environment]::UserInteractive) { throw '-ProfileName is required for -Mode profile.' }
    Write-Section "PROFILES ($($profiles.Count))"
    for ($i = 0; $i -lt $profiles.Count; $i++) {
        Write-Host ("  [{0}] {1,-22} {2}" -f ($i + 1), $profiles[$i].Key, $profiles[$i].Name)
        if ($profiles[$i].Description) { Write-Host ("      {0,-22} {1}" -f '', $profiles[$i].Description) }
    }
    Write-Host ''
    while (-not $ProfileName) {
        $raw = (Read-Host "Profile number or key (blank to cancel)").Trim()
        if (-not $raw) { Write-Host 'Nothing selected - no changes.'; exit 0 }
        if ($raw -match '^\d+$' -and [int]$raw -ge 1 -and [int]$raw -le $profiles.Count) {
            $ProfileName = $profiles[[int]$raw - 1].Key
        } elseif ($profiles.Key -contains $raw) {
            $ProfileName = $raw
        } else {
            Write-Host ("  Unknown. Use 1..{0} or a key: {1}" -f $profiles.Count, ($profiles.Key -join ', '))
        }
    }
}

$prof = $profiles | Where-Object { $_.Key -eq $ProfileName } | Select-Object -First 1
if (-not $prof) { throw "profile '$ProfileName' not found in $($tenant.ProfilesDir). Known: $($profiles.Key -join ', ')" }

# Validate BEFORE touching Azure. A profile that asks for something the engine refuses should
# fail on the file, not halfway through a grant run.
Assert-ProfileSafe -Profile $prof -Tenant $tenant
$profileBackup=Backup-CadmProfileFiles -Tenant $tenant -ProfilePaths @($prof.Path) -Reason 'Profile preview/apply'
Write-Host "Local profile backup: $($profileBackup.Path)"

if (-not $Justification) { $Justification = "$($tenant.JustificationPrefix): $($prof.Name)" }

Write-Section "PROFILE: $($prof.Name)"
Write-Host "  key:    $($prof.Key)"
Write-Host "  file:   $($prof.Path)"
if ($prof.Description) { Write-Host "  intent: $($prof.Description)" }

$acct = Invoke-AzJson -AzArgs @('account', 'show', '-o', 'json')
if (-not $acct) { throw "no active az session ($script:LastAzError). Run: az login" }
Write-Host "  as:     $($acct.user.name)"

$tgt = Resolve-CadmUser -Ref $TargetUser
if (-not $tgt.accountEnabled) { throw "target '$($tgt.userPrincipalName)' is DISABLED - refusing to grant access to it." }
Write-Host "  target: $($tgt.displayName) <$($tgt.userPrincipalName)> $($tgt.id)"

# Directory-role PIM is a SEPARATE consent family from PIM for Groups (*.Directory vs
# *.AzureADGroup). Request it only when the chosen profile actually uses that plane, so a
# group-only profile does not drag Directory consent along with it - and so the operator who
# needs it gets a clear prompt rather than a 403 at grant time.
# Get-ProfileEntries, not @(...): @($null) counts as ONE in PowerShell, so a profile omitting
# the key would read as using the plane and drag Directory consent into every group-only run.
$usesDirRoles = (Get-ProfileEntries $prof.Data.DirectoryRoleEligibilities).Count -gt 0
if ($usesDirRoles) {
    $extra = if ($Apply) { $MgDirWriteScopeList } else { $MgDirReadScopeList }
    $MgScopeList = @($MgScopeList + $extra | Select-Object -Unique)
    $MgScopes = $MgScopeList -join ','
    Write-Host "  note:   profile uses DIRECTORY-ROLE PIM; also requesting $($extra -join ', ')"
}

$usesGroups = (Get-ProfileEntries $prof.Data.PimGroupEligibilities).Count -gt 0 -or
              (Get-ProfileEntries $prof.Data.GroupMemberships).Count -gt 0
if ($usesGroups -or $usesDirRoles) { Connect-GraphIfNeeded -ProbePrincipalId $tgt.id }
$subs = @() # Profile entries already contain exact scopes; each scope is tenant-validated.

$rows = @(Resolve-ProfilePlan -Profile $prof -Target $tgt -Tenant $tenant -Subs $subs)

Show-CadmActivationChecks -Rows $rows
Write-Section 'PLAN'
$rows | Sort-Object Plane, Action, Item |
    Format-Table -AutoSize @{L='Plane';E={$_.Plane}}, @{L='Action';E={$_.Action}},
                            @{L='Role/Group';E={$_.Item}}, @{L='Scope';E={$_.Scope}} |
    Out-String -Width 240 | Write-Host

Write-Host 'Summary:'
foreach ($c in ($rows | Group-Object Action | Sort-Object Name)) { Write-Host ("  {0,-12} {1}" -f $c.Name, $c.Count) }

# Audit JSON is saved before confirmation and updated through completion.
if (-not $OutDir) {
    $OutDir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PIM-Automation/cadm-profile'
}
$runId=[guid]::NewGuid().ToString()
$runDir=Join-Path $OutDir $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$auditFile = Join-Path $runDir 'review.json'
$audit=[ordered]@{
    RunId=$runId;State='Preview';StartedUtc=[datetimeoffset]::UtcNow.ToString('o')
    LauncherVersion=$LauncherVersion;CoreVersion=$CadmCoreVersion;ProfileVersion=$CadmProfileVersion
    TenantId=$tenant.TenantId;Actor=$acct.user.name;Target=$tgt
    Template=$prof.Key;TemplateHash=(Get-CadmFileHash $prof.Path)
    TenantHash=(Get-CadmFileHash $tenant.Path);BackupPath=$profileBackup.Path
    TemplateVersion=$prof.Data.Metadata.Version;Plan=$rows;ApplyRequested=[bool]$Apply
    Coverage='Exact profile assignments only; existing eligibility expiry is retained.'
}
Write-CadmAudit $audit $auditFile
$todo=@($rows | Where-Object Action -eq 'CREATE')
$unknown=@($rows | Where-Object {$_.Action -notin @('CREATE','SKIP-EXISTS')})
if (-not $Apply) {
    Write-Host "DRY RUN - nothing changed. $($todo.Count) grant(s) would be created. Audit: $auditFile"
    if($unknown.Count){Write-Warning "$($unknown.Count) blocked rows; inspect the policy/discovery reasons. This preview cannot be applied.";exit 2}
    exit 0
}
try {
    if($unknown.Count){throw "$($unknown.Count) row(s) are BLOCKED-PIM-UNKNOWN or otherwise blocked."}
    $pimGrpTodo=@($todo | Where-Object Plane -eq 'PIM-GRP')
    $dirTodo=@($todo | Where-Object Plane -eq 'PIM-DIR')
    if($pimGrpTodo.Count -and -not (Test-MgHasScope -Acceptable $MgWriteScopes)){
        throw 'PIM-for-Groups writes require a Graph write scope; no assignments submitted.'
    }
    if($dirTodo.Count -and -not (Test-MgHasScope -Acceptable $MgDirWriteScopes)){
        throw 'Directory-role writes require a Graph directory-role write scope; no assignments submitted.'
    }
    if(-not $Force -and $todo.Count){
        Write-Host "About to create $($todo.Count) grant(s) for $($tgt.userPrincipalName)."
        if($dirTodo.Count){Write-Host 'These make the target ELIGIBLE to activate tenant-wide admin roles.'}
        $confirmation=if($ConfirmTarget){Read-Host "Type APPLY $($tgt.userPrincipalName) to continue"}else{Read-Host 'Type APPLY to continue'}
        $expected=if($ConfirmTarget){"APPLY $($tgt.userPrincipalName)"}else{'APPLY'}
        if($confirmation -cne $expected){
            $audit.State='Cancelled';Write-CadmAudit $audit $auditFile
            Write-Host "Cancelled. No access granted. Audit: $auditFile";exit 0
        }
    }
    if((Get-CadmFileHash $prof.Path) -ne $audit.TemplateHash -or
       (Get-CadmFileHash $tenant.Path) -ne $audit.TenantHash){throw 'Configuration changed since review; preview again.'}
    Assert-CadmAzContext
    $freshTarget=Resolve-CadmUser -Ref $tgt.id
    if(-not $freshTarget.accountEnabled -or $freshTarget.id -ine $tgt.id -or $freshTarget.userPrincipalName -ine $tgt.userPrincipalName){throw 'Target account changed since review.'}
    $fresh=@(Resolve-ProfilePlan -Profile $prof -Target $freshTarget -Tenant $tenant -Subs $subs)
    if((Get-CadmPlanFingerprint $fresh) -cne (Get-CadmPlanFingerprint $rows)){throw 'Access or policy changed since review; preview again.'}
}catch{
    $audit.State='Refused';$audit.Error=$_.Exception.Message;Write-CadmAudit $audit $auditFile
    Write-Host "REFUSING TO APPLY: $($audit.Error) Audit: $auditFile";exit 2
}
$audit.State='Approved';Write-CadmAudit $audit $auditFile
$defaultDuration=if($tenant.DefaultEligibilityDuration){[string]$tenant.DefaultEligibilityDuration}else{'P365D'}
# Invoke-ProfileGrant executes inside the shared audited runner, one assignment at a time.
$outcome=Invoke-CadmAuditedProfileApply -Rows $fresh -Target $freshTarget -Justification $Justification -DefaultDuration $defaultDuration -TicketNumber $TicketNumber -TicketSystem $TicketSystem -RunDirectory $runDir -Context $audit -VerificationAttempts $VerificationAttempts -VerificationDelaySeconds $VerificationDelaySeconds
$audit.State=$outcome.State;$audit.CompletedUtc=$outcome.CompletedUtc
Write-CadmAudit $audit $auditFile
$outcome.Verification | Format-Table Plane,Role,Status,Scope -Wrap | Out-Host
Write-Host "Outcome: $($outcome.State). Audit: $runDir"
if($outcome.State -ne 'Verified'){exit 1}
exit 0
