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

  THREE MODES

    1. Clone (automatic)     - read everything a source user holds, diff, grant the gap.
                               Delegates to Copy-CadmAccess.ps1.
    2. Clone (interactive)   - same, but prints every duplicable grant as a numbered row and
                               grants only the ones you pick.
    3. Apply a profile       - grant a named template. No source user; the template is the
                               intent.

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

  FOUR PLANES a profile can grant:
    Rbac                       standing Azure RBAC at a scope
    GroupMemberships           standing membership of a plain cloud group
    PimGroupEligibilities      PIM for GROUPS - eligible to activate a group's membership
    DirectoryRoleEligibilities standard PIM - eligible to activate an Entra DIRECTORY role

  The last two are different products with different APIs, different scope families and
  SEPARATE CONSENT. A tenant set up for PIM for Groups is not automatically consented for
  directory-role PIM (RoleEligibilitySchedule.ReadWrite.Directory vs *.AzureADGroup); the
  launcher requests the extra scopes only when a profile actually uses that plane.

  Every eligibility is time-bound - never permanent - and clamped to the target's own PIM policy
  ceiling. Set Duration on an entry to pin a term, or leave it for the tenant default.

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

.PARAMETER Mode         clone | interactive | profile. Omit for the menu.
.PARAMETER SourceUser   Template account for the clone modes. UPN, objectId, or UPN prefix.
.PARAMETER TargetUser   Account to grant. Same accepted forms.
.PARAMETER ProfileName  Profile key for -Mode profile - the psd1 file's basename
                        (e.g. 'azure-owner-jit'). Named ProfileName because $Profile is an
                        automatic PowerShell variable and would collide.
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
    [ValidateSet('clone', 'interactive', 'profile')]
    [string]$Mode,
    [string]$SourceUser,
    [string]$TargetUser,
    [string]$ProfileName,
    [switch]$ListProfiles,
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
$LauncherVersion = '1.2.0 (2026-08-20)'

. (Join-Path $PSScriptRoot 'lib\CadmAccess.Core.ps1')
. (Join-Path $PSScriptRoot 'lib\CadmProfile.ps1')

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
            'q' { Write-Host 'Nothing done.'; exit 0 }
            default { Write-Host '  Enter 1, 2, 3, 4 or q.' }
        }
    }
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

    $splat = @{ SourceUser = $SourceUser; TargetUser = $TargetUser; ConnectGraph = $ConnectGraph }
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

Connect-GraphIfNeeded -ProbePrincipalId $tgt.id
$subs = Get-Subscriptions

$rows = @(Resolve-ProfilePlan -Profile $prof -Target $tgt -Tenant $tenant -Subs $subs)

Write-Section 'PLAN'
$rows | Sort-Object Plane, Action, Item |
    Format-Table -AutoSize @{L='Plane';E={$_.Plane}}, @{L='Action';E={$_.Action}},
                            @{L='Role/Group';E={$_.Item}}, @{L='Scope';E={$_.Scope}} |
    Out-String -Width 240 | Write-Host

Write-Host 'Summary:'
foreach ($c in ($rows | Group-Object Action | Sort-Object Name)) { Write-Host ("  {0,-12} {1}" -f $c.Name, $c.Count) }

# Audit JSON for every run, dry or not - the record of what a privileged tool was asked to do
# matters as much as what it did.
if (-not $OutDir) {
    $OutDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "PIM-Automation\cadm-clone\$(Get-Date -Format 'yyyy-MM-dd')"
}
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$auditFile = Join-Path $OutDir "profile-$($prof.Key)-to-$(($tgt.userPrincipalName -split '@')[0])-$stamp.json"
@{
    launcherVersion = $LauncherVersion; coreVersion = $CadmCoreVersion; profileVersion = $CadmProfileVersion
    tenant = @{ name = $tenant.Name; id = $tenant.TenantId; config = $tenant.Path }
    profile = @{ key = $prof.Key; name = $prof.Name; file = $prof.Path }
    target = @{ upn = $tgt.userPrincipalName; id = $tgt.id }
    runAs = $acct.user.name; apply = [bool]$Apply; timestamp = (Get-Date).ToString('o')
    plan = $rows
} | ConvertTo-Json -Depth 8 | Set-Content -Path $auditFile -Encoding utf8

$todo = @($rows | Where-Object { $_.Action -eq 'CREATE' })

# An unreadable PIM plane means the plan was written from a blind spot. Report it loudly and
# refuse to apply rather than granting the readable half and implying parity.
$unknown = @($rows | Where-Object { $_.Action -eq 'BLOCKED-PIM-UNKNOWN' })
if ($unknown.Count) {
    Write-Host ''
    # Name the actual planes. There are two independent ones with separate consent, so a message
    # that always blames PIM-for-Groups sends the operator to fix the wrong scope.
    $unknownPlanes = @($unknown | ForEach-Object { $_.Plane } | Sort-Object -Unique) -join ', '
    Write-Host "  [WARN] $($unknown.Count) eligibility row(s) could not be checked - plane(s) $unknownPlanes"
    Write-Host '         were not readable. That is an UNKNOWN, not a no. Fix the Graph session'
    Write-Host '         (drop -ConnectGraph:$false, or Disconnect-MgGraph and re-run) before applying.'
    foreach ($u in $unknown) { Write-Host "           - $($u.Plane) $($u.Item): $($u.Detail)" }
}

if (-not $Apply) {
    Write-Host ''
    Write-Host "[OK] plan written to $auditFile"
    Write-Host ''
    Write-Host "DRY RUN - nothing changed. $($todo.Count) grant(s) would be created."
    Write-Host 'Re-run with -Apply to perform them.'
    exit 0
}
if ($unknown.Count) {
    Write-Host ''
    Write-Host "REFUSING TO APPLY: $($unknown.Count) row(s) are BLOCKED-PIM-UNKNOWN. Applying now would"
    Write-Host 'grant the readable planes while the eligibility state stays unverified.'
    exit 2
}
if ($todo.Count -eq 0) { Write-Host ''; Write-Host 'Nothing to do - target already matches this profile.'; exit 0 }

# Same refusal as the clone path: PIM-for-Groups writes need a write scope, and half-applying
# leaves the target holding standing roles but none of the activate-on-demand access.
$pimGrpTodo = @($todo | Where-Object { $_.Plane -eq 'PIM-GRP' })
if ($pimGrpTodo.Count -and -not (Test-MgHasScope -Acceptable $MgWriteScopes)) {
    Write-Host ''
    Write-Host "REFUSING TO APPLY: $($pimGrpTodo.Count) PIM-for-Groups grant(s) are planned, but this"
    Write-Host 'Graph session holds no write scope - they would all fail while the RBAC and group'
    Write-Host 'grants succeeded, leaving a partial apply that looks finished.'
    Write-Host ''
    Write-Host ('  scopes held: ' + $(if ($script:MgScopesHeld.Count) { $script:MgScopesHeld -join ', ' } else { '(none)' }))
    Write-Host ("  need one of: " + ($MgWriteScopes -join ', '))
    exit 2
}

# Directory-role writes need their own scope. Same reasoning as the group-plane refusal: a
# partial apply that grants the readable planes and silently drops the privileged one is worse
# than not starting.
$dirTodo = @($todo | Where-Object { $_.Plane -eq 'PIM-DIR' })
if ($dirTodo.Count -and -not (Test-MgHasScope -Acceptable $MgDirWriteScopes)) {
    Write-Host ''
    Write-Host "REFUSING TO APPLY: $($dirTodo.Count) directory-role eligibility grant(s) are planned,"
    Write-Host 'but this Graph session holds no directory-role write scope.'
    Write-Host ''
    Write-Host ('  scopes held: ' + $(if ($script:MgScopesHeld.Count) { $script:MgScopesHeld -join ', ' } else { '(none)' }))
    Write-Host ("  need one of: " + ($MgDirWriteScopes -join ', '))
    Write-Host ''
    Write-Host '  This is a SEPARATE consent from the PIM-for-Groups scopes - a tenant consented'
    Write-Host '  for groups is not consented for directory roles. Grant it to this account, then'
    Write-Host '  Disconnect-MgGraph and re-run.'
    exit 2
}

if (-not $Force) {
    Write-Host ''
    Write-Host "About to create $($todo.Count) grant(s) for $($tgt.userPrincipalName) from profile '$($prof.Name)'."
    if ($dirTodo.Count) {
        Write-Host ''
        Write-Host "  ** $($dirTodo.Count) DIRECTORY-ROLE eligibility grant(s): $(($dirTodo.Item | Sort-Object -Unique) -join ', ')"
        Write-Host '     These make the target ELIGIBLE to activate tenant-wide admin roles.'
        Write-Host '     Activation gates (MFA, approval, duration) come from each role PIM policy -'
        Write-Host '     confirm those are configured before relying on this as a control.'
    }
    if ((Read-Host 'Type APPLY to continue') -ne 'APPLY') { Write-Host 'Aborted.'; exit 0 }
}

$defaultDuration = if ($tenant.DefaultEligibilityDuration) { [string]$tenant.DefaultEligibilityDuration } else { 'P365D' }
$res = Invoke-ProfileGrant -Rows $todo -Target $tgt -Justification $Justification `
                           -TicketNumber $TicketNumber -TicketSystem $TicketSystem `
                           -DefaultDuration $defaultDuration

Write-Host ''
Write-Host "Invoke-CadmAccess done: $($res.Ok) granted, $($res.Fail) failed. Audit: $auditFile"
if ($res.Fail) { exit 1 }
exit 0
