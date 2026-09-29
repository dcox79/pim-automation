#requires -Version 5.1

<#
.SYNOPSIS
  Clone one CADM account's Azure access onto another: Azure RBAC, Azure-resource PIM,
  PIM for Groups, and plain group membership. Dry-run by default; -Apply performs the grants.

.DESCRIPTION
  Reads every access grant the SOURCE principal holds, diffs it against the TARGET, and emits
  a plan. Nothing is written without -Apply.

  ---------------------------------------------------------------------------------------
  QUICK START
  ---------------------------------------------------------------------------------------
  Needs a current `az login` and the Microsoft.Graph.Authentication module.

  NOT STANDALONE since v1.22.0. The engine lives in scripts/cadm/lib/CadmAccess.Core.ps1 and is
  dot-sourced from a path relative to this file, so copy the scripts/cadm folder alongside it -
  the folder is the unit of handoff, not this file. The banner prints both versions, so a
  mismatched pair is visible on the first line of any run.

  There is also a launcher, scripts/cadm/Invoke-CadmAccess.ps1, which adds a menu, enforces a
  per-tenant binding, and can apply PROFILE TEMPLATES instead of cloning. Prefer a profile for a
  NEW account: a clone copies whatever the source actually holds, drift included. This script
  remains the right tool for deliberately mirroring a peer, or for auditing what a template
  account would propagate.

  EDITION: runs on both pwsh 7.x and Windows PowerShell 5.1 - no version-specific syntax
  (subexpressions rather than ternaries, no -SkipHttpErrorCheck, no parallel ForEach). The
  RBAC and Azure-resource PIM planes are verified identical on both. The PIM-for-Groups plane
  goes through Microsoft.Graph.Authentication and has been exercised on 7.x only; if it
  misbehaves on 5.1 the run degrades safely - an unreadable plane BLOCKS permanent group
  grants rather than guessing (see BLOCKED-PIM-UNKNOWN). Prefer 7.x where you have it.
  Note 5.1 writes the audit JSON as UTF-8 with a BOM; 7.x writes it without.

  1. Dry run. Reads, diffs, prints the plan, writes audit JSON. Changes NOTHING:

       .\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin -TargetUser target-admin

     Sign-in falls back on its own: it tries the browser, and if that does not complete (normal
     on VDI and locked-down desktops) it retries with a device code - a URL and code you finish
     from any browser. -UseDeviceCode skips straight to that. If the module is missing on the
     host, install it first (no admin needed):
       Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

     Graph PowerShell connects automatically if it is not already (a sign-in window opens) -
     sign in as the account holding the consented PIM-for-Groups scopes and the Entra role to
     use them (Privileged Role Administrator for role-assignable groups). One connection per
     session; later runs reuse it. Disable with -ConnectGraph:$false for unattended runs,
     where an interactive sign-in would hang - the run then degrades to UNREADABLE.

  2. Read the plan. Check three things before going further:
       * the banner says apply=False
       * pimGroupsReadable is True - if False the PIM-for-Groups plane went unread, the plan
         is missing those eligibilities, and permanent group grants are blocked
       * the CREATE rows are access you actually intend to grant

  3. Apply. Prompts for a typed APPLY confirmation unless -Force:

       .\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin -TargetUser target-admin -Apply

  4. Finish the on-prem half. Synced groups cannot be written from Azure; the run emits an
     ad-actions-<target>-<stamp>.ps1 next to the audit JSON. Run it where the ActiveDirectory
     module is available (RSAT / a jump box), as an account that can modify those groups.

  Re-running is safe. Everything already in place is reported SKIP-EXISTS, so a partial or
  failed run can simply be run again.

  Audit output goes to %LOCALAPPDATA%\PIM-Automation\cadm-clone\<date>\ by default - deliberately
  NOT inside the repo, so a checkout or a clean rebuild cannot discard the record of a
  privileged grant. Override with -OutDir.

  Exit codes: 0 = success (or dry run), 1 = at least one grant failed, 2 = refused to apply
  because the Graph session lacks the PIM-for-Groups write scope.
  ---------------------------------------------------------------------------------------

  TWO AUTH PLANES - this is the thing to understand before running it.
    * Azure RBAC + Azure-resource PIM come from ARM and work under plain `az login`.
    * PIM for Groups lives in Microsoft Graph and is NOT reachable from the az CLI: its
      first-party app may lack the required PIM-for-Groups permissions. This plane uses
      Microsoft Graph PowerShell (Microsoft.Graph.Authentication). Appropriate tenant consent
      must be configured before use. Example connection:

        Connect-MgGraph -Scopes PrivilegedAccess.ReadWrite.AzureADGroup,PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup,Group.Read.All,User.Read.All

      Without that connection the PIM-for-Groups plane is reported UNREADABLE - which is NOT
      the same as "none", and the script says so loudly rather than implying parity.
    Microsoft.Graph is not Az PowerShell; no Connect-AzAccount / Get-Az* is used anywhere.

  WHAT IT COPIES
    1. Azure RBAC assignments held DIRECTLY by the source (principalType=User), at true scope.
    2. Azure-resource PIM eligibilities, mirroring the source's expiration.
    3. PIM for Groups eligibilities (member and owner), mirroring expiration.
    4. Membership of CLOUD-ONLY groups that are NOT PIM-managed.

  WHAT IT DELIBERATELY DOES NOT COPY - and why
    * A PIM-managed group as a PERMANENT member. When a principal activates a PIM-for-Groups
      eligibility, the activation shows up in /memberOf exactly like a standing membership.
      Cloning that naively would hand the target permanent membership of a group the source
      only holds on an activate-when-needed basis - a silent privilege escalation that also
      escapes the PIM audit trail. Every group carrying a PIM eligibility or an active PIM
      assignment is therefore subtracted from the permanent-membership plan and copied as an
      eligibility instead.
    * Group-derived RBAC. An assignment whose principalType is Group is inherited, not held.
      Recreating it directly would grant the same access on a path that survives removal from
      the group. Reported as informational; the group plan is what actually conveys it.
    * ON-PREM SYNCED groups. Mastered in Active Directory; Graph rejects member writes on them
      ("Unable to update the specified properties for objects that have originated within an
      external service"). The script emits a ready-to-run Add-ADGroupMember list instead.
    * Root-scope grants (scope '/'). User Access Administrator at '/' is normally the transient
      artifact of a Global Admin elevating; it lets the holder grant any role anywhere in the
      tenant, including to themselves. Excluded unless -AllowRootScope.
    * PIM POLICY settings (activation duration, MFA, approvers). These belong to a role+scope
      (roleManagementPolicy), NOT to a user - two principals eligible for the same role at the
      same scope share one policy. There is nothing user-specific to copy; the target inherits
      the identical policy automatically.

.PARAMETER SourceUser   Template account. UPN, objectId, or UPN prefix (e.g. 'source-admin').
.PARAMETER TargetUser   Account to grant. Same accepted forms.
.PARAMETER Apply        Perform the grants. Omit for a dry run (the default).
.PARAMETER AllowRootScope  Include grants at scope '/'. Off by default.
.PARAMETER SkipGroups   Skip both group planes (PIM for Groups and permanent membership).
.PARAMETER SkipPim      Skip Azure-resource PIM.
.PARAMETER SkipPimRoleCheck
                        Bypass the directory-role preflight on PIM-for-Groups writes and let
                        Graph return the real answer. Use when authority comes from something
                        the check cannot see - chiefly being an ACTIVE OWNER of the group, which
                        MS Learn accepts in place of any directory role. Scopes are still
                        checked; this only relaxes the ROLE gate.
.PARAMETER IncludePimActive
                        Second-step opt-in for groups reported BLOCKED-PIM-ACTIVE. The source
                        holds these via a PIM ACTIVE assignment with no eligibility behind it, so
                        there is nothing to clone faithfully. This grants the target an
                        ELIGIBILITY on each - the ability to activate, without standing access -
                        rather than copying the live assignment. Review the NOT CLONED section
                        first; this is a deliberate decision, not a default.
.PARAMETER Interactive  Pick-and-choose mode. Reads everything the source holds, prints every
                        grant that CAN be duplicated as a numbered row - including root-scope
                        grants and PIM-ACTIVE promotions that a normal run excludes by default,
                        clearly labeled - then prompts for a comma-separated list of numbers to
                        clone ('all' for everything, blank to cancel). Only the selection is
                        granted, after the usual typed APPLY confirmation. Implies -Apply.
.PARAMETER Force        With -Apply, skip the interactive confirmation.
.PARAMETER ConnectGraph Auto-connect Graph PowerShell when there is no session holding the
                        PIM-for-Groups write scope. Default $true. Pass -ConnectGraph:$false
                        for unattended runs, where an interactive sign-in would hang.
.PARAMETER UseDeviceCode Sign in with a device code (a URL + code printed to the console)
                        instead of the browser redirect. Use on VDI / locked-down desktops
                        where no usable default browser exists; you can complete it from a
                        browser on any machine.
.PARAMETER OutDir       Audit directory. Default %LOCALAPPDATA%\PIM-Automation\cadm-clone\<yyyy-MM-dd>\
                        (or $HOME/PIM-Automation/... off Windows). Intentionally outside the repo so
                        the record of a privileged grant survives a checkout or clean rebuild.

.EXAMPLE
  .\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin -TargetUser target-admin
  Dry run. Prints the plan, writes audit JSON, changes nothing.

.EXAMPLE
  .\scripts\Copy-CadmAccess.ps1 -SourceUser source-admin -TargetUser target-admin -Apply

.NOTES
  CADM UPN domains are inconsistent (source-admin@example.com vs
  target-admin@example.net), so the resolver falls back to a prefix search.

  Git Bash only: `export MSYS_NO_PATHCONV=1` first, or MG scope strings beginning
  '/providers/...' get rewritten into Windows paths. Not an issue in pwsh.

  Output is ASCII-only (cp1252-safe for Tee-Object / redirect capture).

  EDITING THIS HELP BLOCK - three rules, and breaking any of them makes Get-Help silently
  return only the auto-generated syntax, hiding every instruction above unless you open the
  file in an editor:
    1. Exactly one blank line between the requires statement and the opening comment marker,
       with NO comment lines in between. A single hash-comment there breaks the binding.
    2. At least two blank lines between the closing comment marker and the first line of code.
    3. Never write the closing comment marker sequence inside this block, even in prose or
       backticks - it terminates the block early and the remaining help text is then parsed
       as code. Describe the markers in words, as done here.
  Verify after editing:  Get-Help .\scripts\Copy-CadmAccess.ps1 -Full
  A non-empty .DESCRIPTION means it bound; tests/identity guards this.
#>

# NOTE: the two blank lines above are load-bearing. PowerShell only binds a comment block as
# SCRIPT help when it is separated from the first code line by at least two blank lines -
# otherwise Get-Help silently falls back to the auto-generated syntax and every instruction
# above becomes invisible unless you open the file. Do not close this gap.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceUser,
    [Parameter(Mandatory = $true)][string]$TargetUser,
    [switch]$Apply,
    [switch]$AllowRootScope,
    [switch]$SkipGroups,
    [switch]$SkipPim,
    [switch]$SkipPimRoleCheck,
    [switch]$IncludePimActive,
    [switch]$Interactive,
    [switch]$Force,
    # Default ON: connect Graph PowerShell automatically when there is no usable session.
    # A [bool] rather than a [switch] because switches cannot default to true - disable with
    # -ConnectGraph:$false (e.g. unattended runs, where an interactive sign-in would hang).
    [bool]$ConnectGraph = $true,
    # VDI / locked-down desktops often have no usable default browser, so the interactive
    # redirect never completes. Device code prints a URL + code to the console instead, which
    # you can complete from any browser (including one on a different machine).
    [switch]$UseDeviceCode,
    [string]$OutDir,
    [string]$Justification = 'Access clone via Copy-CadmAccess.ps1',
    [string]$TicketNumber = '',
    [string]$TicketSystem = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Printed in the startup banner. This script gets COPIED between hosts rather than always run
# from a checkout, so "which version am I holding?" cannot be answered by git. Bump this on any
# behavioural change; the banner is then the fastest way to tell a stale copy from a current
# one - three separate troubleshooting rounds were spent on a copy that predated a safety fix.
$ScriptVersion = '1.23.0 (2026-08-19)'


# The engine lives in scripts/cadm/lib/CadmAccess.Core.ps1 (see the header there for why it is
# dot-sourced rather than a module). This script is therefore NO LONGER STANDALONE - hand it off
# together with the scripts/cadm folder; the banner below prints both versions so a mismatched
# pair is visible at a glance.
. (Join-Path $PSScriptRoot 'cadm\lib\CadmAccess.Core.ps1')

# ---------------------------------------------------------------------------
# Resolve principals
# ---------------------------------------------------------------------------

Write-Host "Copy-CadmAccess v$ScriptVersion (core v$CadmCoreVersion)"
Write-Host "  source='$SourceUser' target='$TargetUser' apply=$($Apply.IsPresent) $(Get-Date -Format o)"

Initialize-AzInvoker
Write-Host "  az invoker: $script:AzExe"

# Fail fast on a missing az session. Everything downstream - user lookup, subscriptions, RBAC,
# Azure-resource PIM - runs through az, so without a session the first symptom is a confusing
# "could not resolve <user>" that reads like a bad account name.
$azAcct = Invoke-AzJson -AzArgs @('account', 'show', '-o', 'json')
if (-not $azAcct) {
    throw ("no active az session ($script:LastAzError). Run: az login --use-device-code " +
           "(device code avoids the WAM broker, which fails on many VDI hosts).")
}
Write-Host "  az account: $($azAcct.user.name)"

$src = Resolve-CadmUser -Ref $SourceUser
$tgt = Resolve-CadmUser -Ref $TargetUser
if ($src.id -eq $tgt.id) { throw 'source and target are the same account - nothing to do.' }
if (-not $tgt.accountEnabled) { throw "target '$($tgt.userPrincipalName)' is DISABLED - refusing to grant access to it." }

Write-Host "  source: $($src.displayName) <$($src.userPrincipalName)> $($src.id)"
Write-Host "  target: $($tgt.displayName) <$($tgt.userPrincipalName)> $($tgt.id)"

$subs = Get-Subscriptions
Write-Host "  scanning $($subs.Count) subscription(s) - five sweeps, roughly $([int]($subs.Count * 5 * 2.5 / 60)) min"

# ---------------------------------------------------------------------------
# Read current state
# ---------------------------------------------------------------------------

$srcRa = Get-RoleAssignmentsFor -PrincipalId $src.id -Subs $subs -Label 'source role assignments '
$tgtRa = Get-RoleAssignmentsFor -PrincipalId $tgt.id -Subs $subs -Label 'target role assignments '

$srcPim = @{ Map = [ordered]@{}; Denied = $false }
$tgtPim = @{ Map = [ordered]@{}; Denied = $false }
$srcActivated = @{ Map = [ordered]@{}; Denied = $false }
if (-not $SkipPim) {
    $srcPim = Get-PimResourceFor -PrincipalId $src.id -Subs $subs -Label 'source PIM eligibilities'
    $tgtPim = Get-PimResourceFor -PrincipalId $tgt.id -Subs $subs -Label 'target PIM eligibilities'
    $srcActivated = Get-PimActivatedFor -PrincipalId $src.id -Subs $subs
}

$mgOk = $false
$srcPimGrp = @{ Ok = $false; Error = 'not attempted'; Map = [ordered]@{}; ActiveGroupIds = @(); ActiveMap = @{} }
$tgtPimGrp = @{ Ok = $false; Error = 'not attempted'; Map = [ordered]@{}; ActiveGroupIds = @(); ActiveMap = @{} }
$srcGroups = @(); $tgtGroupIds = @()
$pimRoleStatus = 'unknown'
if (-not $SkipGroups) {
    Connect-GraphIfNeeded -ProbePrincipalId $src.id
    $mgOk = Test-MgConnected
    if ($mgOk) {
        # Check the directory role EARLY. Failing at -Apply after a full scan wastes the run,
        # and the usual cause is simply forgetting to activate an eligible role in PIM.
        $pimRoleStatus = Get-MgPimRoleStatus

        # Print the two gates on EVERY run, not only when one of them fails. Delegated access is
        # scope AND role; a 403 names neither, and without these lines diagnosing one costs a
        # round-trip per guess. Three separate sessions were spent that way.
        Write-Host ("  graph roles:  " + $(if ($script:PimRoleHeld.Count) { $script:PimRoleHeld -join ', ' } else { '(none detected)' }))
        # Labelled 'requested' deliberately: this list can echo what Connect-MgGraph asked for
        # rather than what the tenant granted. The probe above is the authority, not this.
        Write-Host ("  graph scopes: " + $(if ($script:MgScopesHeld.Count) { ($script:MgScopesHeld -join ', ') + '  (requested; not proof of grant)' } else { '(none reported)' }))

        if ($pimRoleStatus -eq 'missing') {
            Write-Host ''
            Write-Host '  [WARN] the signed-in Graph account holds no directory role permitting'
            Write-Host '         PIM-for-Groups writes. Most often this means an eligible role was'
            Write-Host '         not ACTIVATED in PIM before connecting.'
            Write-Host ("         need one of: " + ($(if ($Apply) { $PimGroupWriteRoles } else { $PimGroupReadRoles }) -join ', '))
            if (-not $Apply) {
                Write-Host '         For READS, Global Administrator does NOT qualify - Global Reader does.'
                Write-Host '         A GA-only break-glass account is refused 403 here; add Global Reader to it.'
            }
            Write-Host '         Or be an ACTIVE OWNER of the group - not visible here; use -SkipPimRoleCheck.'
            Write-Host '         Activate in PIM, then Disconnect-MgGraph and re-run - the role is'
            Write-Host '         baked into the token at sign-in, so an existing session will not pick it up.'
        }
    }
    if ($mgOk) {
        $srcPimGrp = Get-PimGroupsFor -PrincipalId $src.id
        $tgtPimGrp = Get-PimGroupsFor -PrincipalId $tgt.id
    }
    $srcGroups   = Get-GroupsFor -PrincipalId $src.id
    $tgtGroupIds = @((Get-GroupsFor -PrincipalId $tgt.id) | ForEach-Object { $_.id })
}

# Groups whose access is PIM-managed for the SOURCE. Membership of these must never be cloned
# as a permanent add - see .DESCRIPTION. Covers both a standing eligibility and a currently
# activated one (the latter is indistinguishable from a real membership in /memberOf).
# Two DIFFERENT kinds of PIM-managed group, and conflating them silently drops access.
#   eligible  - source can activate it. Cloned as an eligibility (a PIM-GRP CREATE row).
#   activeOnly- source holds it as a PIM *Active* assignment with no eligibility behind it.
#               This script only creates eligibilities, so there is nothing to clone - and it
#               must NOT be granted as permanent membership either, since PIM owns it. Left
#               unseparated, such a group was excluded from the membership plan and never
#               appeared in the eligibility plan, so it vanished from the run entirely while
#               the row claimed it had been "copied as an eligibility".
$pimEligibleGroupIds = @{}
foreach ($k in $srcPimGrp.Map.Keys) { $pimEligibleGroupIds[$srcPimGrp.Map[$k].GroupId] = $true }
$pimActiveOnlyIds = @{}
foreach ($g in $srcPimGrp.ActiveGroupIds) {
    if (-not $pimEligibleGroupIds.ContainsKey($g)) { $pimActiveOnlyIds[$g] = $true }
}

# ---------------------------------------------------------------------------
# Build the plan
# ---------------------------------------------------------------------------

$plan = [System.Collections.Generic.List[object]]::new()

# Comparison key deliberately omits principalId - the source and target ARE different
# principals, so "does the target already hold this role at this scope" is a (role, scope)
# question. Only the target's own direct (User) assignments count as already-held.
$tgtRaKeys = @{}
foreach ($k in $tgtRa.Keys) {
    $t = $tgtRa[$k]
    if ($t.principalType -eq 'Group') { continue }
    $tgtRaKeys["$(Get-RoleDefGuid $t.roleDefinitionId)|$($t.scope)".ToLower()] = $true
}

foreach ($key in $srcRa.Keys) {
    $r = $srcRa[$key]
    if ($r.principalType -eq 'Group') {
        $plan.Add([pscustomobject]@{ Plane='RBAC'; Action='INFO-VIA-GROUP'; Item=$r.roleDefinitionName
                                     Scope=$r.scope; Detail='inherited from a group; conveyed by the group plan' })
        continue
    }
    if ($r.scope -eq $RootScope -and -not $AllowRootScope) {
        $plan.Add([pscustomobject]@{ Plane='RBAC'; Action='EXCLUDED-ROOT'; Item=$r.roleDefinitionName
                                     Scope=$r.scope; Detail='root scope; pass -AllowRootScope to include' })
        continue
    }
    $cmp = "$(Get-RoleDefGuid $r.roleDefinitionId)|$($r.scope)".ToLower()

    # Currently-ACTIVATED PIM elevation, not standing access. Cloning it would make the
    # source's temporary elevation permanent for the target - the same escalation as
    # SKIP-PIM-MANAGED on the group plane, and far worse in reach: the live example was Owner
    # at Tenant Root Group.
    if ($srcActivated.Map.Contains($cmp)) {
        $a = $srcActivated.Map[$cmp]
        $plan.Add([pscustomobject]@{
            Plane='RBAC'; Action='SKIP-PIM-ACTIVATED'; Item=$r.roleDefinitionName; Scope=$r.scope
            Detail="temporary PIM elevation (expires $($a.EndsAt)); not standing access" })
        continue
    }
    # PIM data unavailable means an activation cannot be told from a standing grant. Refuse
    # rather than guess - do not silently promote someone's elevation into a permanent grant.
    if ($SkipPim -or $srcActivated.Denied) {
        $plan.Add([pscustomobject]@{
            Plane='RBAC'; Action='BLOCKED-PIM-UNKNOWN'; Item=$r.roleDefinitionName; Scope=$r.scope
            Detail='cannot tell a standing grant from an active PIM elevation; drop -SkipPim' })
        continue
    }
    $plan.Add([pscustomobject]@{
        Plane='RBAC'; Action=$(if ($tgtRaKeys.ContainsKey($cmp)) { 'SKIP-EXISTS' } else { 'CREATE' })
        Item=$r.roleDefinitionName; Scope=$r.scope; Detail=(Get-RoleDefGuid $r.roleDefinitionId) })
}

foreach ($key in $srcPim.Map.Keys) {
    $e = $srcPim.Map[$key]
    if ($e.Scope -eq $RootScope -and -not $AllowRootScope) {
        $plan.Add([pscustomobject]@{ Plane='PIM-RES'; Action='EXCLUDED-ROOT'; Item=$e.RoleName
                                     Scope=$e.Scope; Detail='root scope; pass -AllowRootScope' })
        continue
    }
    $plan.Add([pscustomobject]@{
        Plane='PIM-RES'; Action=$(if ($tgtPim.Map.Contains($key)) { 'SKIP-EXISTS' } else { 'CREATE' })
        Item=$e.RoleName; Scope=$e.Scope
        Detail=$(if ($e.EndDateTime) { "until $($e.EndDateTime)" } else { 'no expiry' }) })
}

if (-not $SkipGroups -and $srcPimGrp.Ok) {
    foreach ($key in $srcPimGrp.Map.Keys) {
        $e = $srcPimGrp.Map[$key]
        $plan.Add([pscustomobject]@{
            Plane='PIM-GRP'; Action=$(if ($tgtPimGrp.Ok -and $tgtPimGrp.Map.Contains($key)) { 'SKIP-EXISTS' } else { 'CREATE' })
            Item="$(Get-GroupName -GroupId $e.GroupId) [$($e.AccessId)]"; Scope=$e.GroupId
            AccessId=$e.AccessId
            Detail=$(if ($e.EndDateTime) { "until $($e.EndDateTime)" } else { 'no expiry' }) })
    }
}

$adActions = [System.Collections.Generic.List[string]]::new()
foreach ($g in $srcGroups) {
    if ($pimEligibleGroupIds.ContainsKey($g.id)) {
        $plan.Add([pscustomobject]@{ Plane='GROUP'; Action='SKIP-PIM-MANAGED'; Item=$g.displayName; Scope=$g.id
                                     Detail='PIM eligibility for the source; re-created as an eligibility below, not as permanent membership' })
        continue
    }
    if ($pimActiveOnlyIds.ContainsKey($g.id)) {
        # Held via a PIM ACTIVE assignment with no eligibility behind it. Not cloned by default -
        # granting permanent membership would take it outside PIM, converting the source's
        # on-demand access into the target's standing access. Surfaced for a deliberate decision,
        # never dropped.
        #
        # -IncludePimActive is that decision, made explicitly. It grants an ELIGIBILITY rather
        # than a copy of the active assignment: the target gets the ability to activate, which is
        # the durable half of what the source has, without standing access. Copying the active
        # assignment instead would hand over live access AND expire on the source's clock.
        if ($IncludePimActive) {
            $acc = if ($srcPimGrp.ActiveMap -and $srcPimGrp.ActiveMap[$g.id]) { $srcPimGrp.ActiveMap[$g.id] } else { 'member' }
            $plan.Add([pscustomobject]@{
                Plane='PIM-GRP'; Action='CREATE'; Item="$($g.displayName) [$acc]"; Scope=$g.id
                AccessId=$acc
                Detail='promoted from BLOCKED-PIM-ACTIVE by -IncludePimActive; granted as an ELIGIBILITY, not standing access' })
            continue
        }
        $plan.Add([pscustomobject]@{ Plane='GROUP'; Action='BLOCKED-PIM-ACTIVE'; Item=$g.displayName; Scope=$g.id
                                     Detail='source holds a PIM ACTIVE assignment (no eligibility); -IncludePimActive grants the target an eligibility instead' })
        continue
    }
    if ($tgtGroupIds -contains $g.id) {
        $plan.Add([pscustomobject]@{ Plane='GROUP'; Action='SKIP-EXISTS'; Item=$g.displayName; Scope=$g.id; Detail='' })
        continue
    }
    # Without the PIM-for-Groups plane we CANNOT tell a standing membership from an activated
    # eligibility - both look identical in /memberOf. Granting permanent membership on that
    # guess is the exact escalation the SKIP-PIM-MANAGED path exists to prevent, so refuse to
    # grant rather than assume "not PIM-managed". Blocks, never silently downgrades.
    if (-not $srcPimGrp.Ok) {
        $plan.Add([pscustomobject]@{
            Plane='GROUP'; Action='BLOCKED-PIM-UNKNOWN'; Item=$g.displayName; Scope=$g.id
            Detail='cannot tell standing membership from an activated PIM eligibility; connect Graph PowerShell' })
        continue
    }
    if ($g.onPremisesSyncEnabled) {
        $plan.Add([pscustomobject]@{ Plane='GROUP'; Action='BLOCKED-ONPREM'; Item=$g.displayName; Scope=$g.id
                                     Detail='on-prem synced; must be done in Active Directory' })
        $adActions.Add("Add-ADGroupMember -Identity '$($g.displayName)' -Members '$(($tgt.userPrincipalName -split '@')[0])'")
        continue
    }
    $plan.Add([pscustomobject]@{ Plane='GROUP'; Action='CREATE'; Item=$g.displayName; Scope=$g.id; Detail='cloud-only' })
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

Write-Section 'PLAN'
$plan | Sort-Object Plane, Action, Item |
    Format-Table -AutoSize @{L='Plane';E={$_.Plane}}, @{L='Action';E={$_.Action}},
                            @{L='Role/Group';E={$_.Item}}, @{L='Scope';E={$_.Scope}} |
    Out-String -Width 240 | Write-Host

Write-Host 'Summary:'
foreach ($c in ($plan | Group-Object Action | Sort-Object Name)) { Write-Host ("  {0,-18} {1}" -f $c.Name, $c.Count) }

# ---------------------------------------------------------------------------
# NOT CLONED - everything the run will not carry across, and what to do about it
# ---------------------------------------------------------------------------
# The plan table lists actions; this answers the question an operator actually asks afterwards,
# which is "what did I NOT get, and what do I do now?". Without it the blocked rows are scattered
# through a 25-line table sorted by plane, and the remedy for each lives only in this runbook.
$notClonedRemedy = [ordered]@{
    'BLOCKED-ONPREM'      = 'Run the AD actions file below where the ActiveDirectory module is available.'
    'BLOCKED-PIM-ACTIVE'  = 'Source holds these via PIM ACTIVE with no eligibility. Re-run with -IncludePimActive to grant the target an ELIGIBILITY instead, or grant deliberately in PIM.'
    'BLOCKED-PIM-UNKNOWN' = 'The PIM-for-Groups plane was not read, so standing membership cannot be told from an activated eligibility. Fix the Graph session and re-run - this is an unknown, not a no.'
    'EXCLUDED-ROOT'       = 'Grants at root scope "/" are excluded by default. Re-run with -AllowRootScope to include them.'
    'SKIP-PIM-ACTIVATED'  = 'Source was temporarily elevated through PIM when scanned. NOT standing access - do not grant these by hand either.'
}
$notCloned = @($plan | Where-Object { $notClonedRemedy.Contains($_.Action) })
if ($notCloned.Count) {
    Write-Section "NOT CLONED ($($notCloned.Count))"
    foreach ($action in $notClonedRemedy.Keys) {
        $rows = @($notCloned | Where-Object { $_.Action -eq $action })
        if (-not $rows.Count) { continue }
        Write-Host ''
        Write-Host "  $action ($($rows.Count))"
        foreach ($r in $rows) { Write-Host "    - $($r.Item)" }
        Write-Host "    -> $($notClonedRemedy[$action])"
    }
    $pimActiveRows = @($notCloned | Where-Object { $_.Action -eq 'BLOCKED-PIM-ACTIVE' })
    if ($pimActiveRows.Count) {
        Write-Host ''
        Write-Host '  Second step - clone the PIM-ACTIVE groups as eligibilities:'
        $extra = if ($Apply) { ' -Apply' } else { '' }
        Write-Host "    .\scripts\Copy-CadmAccess.ps1 -SourceUser $SourceUser -TargetUser $TargetUser -IncludePimActive$extra"
    }
    Write-Host ''
}

if ($Apply -and -not $SkipGroups -and $srcPimGrp.Ok -and -not (Test-MgHasScope -Acceptable $MgWriteScopes)) {
    # Only meaningful when applying. A dry run deliberately connects read-only, so flagging a
    # read-only session there would be noise on every single report-only run.
    Write-Section 'PIM FOR GROUPS - READ-ONLY SESSION'
    Write-Host '  This session can READ PIM for Groups but not write it, so -Apply will refuse'
    Write-Host '  rather than half-apply. Reconnect with write scopes:'
    Write-Host ''
    Write-Host "    Connect-MgGraph -Scopes $($MgWriteScopeList -join ',')"
}

if (-not $SkipGroups -and -not $srcPimGrp.Ok) {
    Write-Section 'PIM FOR GROUPS - UNREADABLE'
    Write-Host '  This plane was NOT read. That is not the same as "none" - do not treat this run'
    Write-Host '  as achieving parity.'
    Write-Host ''
    # Do NOT hand out a Connect-MgGraph line here. This message used to print the READ scope set,
    # and an operator following it in a tenant that only consents the ReadWrite pair got a session
    # that reported healthy and 403'd - then that manual session made the script skip its own
    # broader-scope retry. The advice caused the failure it was printed to fix. Let the script
    # connect; it tries least privilege first and widens on refusal.
    Write-Host '  Drop any existing session and let this script connect - it requests least'
    Write-Host '  privilege first and widens automatically if the tenant refuses:'
    Write-Host ''
    Write-Host '    Disconnect-MgGraph'
    Write-Host ''
    Write-Host '  Connecting by hand is the usual cause of this: a session that reports the right'
    Write-Host "  scopes is not proof the tenant granted them, and it suppresses the retry."
    Write-Host ''
    # Prefer whatever real error we have. "no session" is only the reason when there genuinely
    # never was one - it must not mask a 403 the probe already explained.
    if ($srcPimGrp.Error -and $srcPimGrp.Error -ne 'not attempted') { Write-Host "  reason: $($srcPimGrp.Error)" }
    elseif ($script:MgProbeError) { Write-Host "  reason: $($script:MgProbeError)" }
    elseif (-not $mgOk) { Write-Host '  reason: Microsoft.Graph.Authentication not loaded / no Get-MgContext session.' }
    else { Write-Host '  reason: unknown - the plane was not read and no error was captured.' }
    Write-Host ''
    Write-Host '  If the directory says you HAVE the role and the consent, suspect a stale token.'
    Write-Host '  Windows brokers this sign-in through WAM, whose cache survives Disconnect-MgGraph,'
    Write-Host '  so a newly added role or newly consented scope may never reach the token. Re-run'
    Write-Host '  with -UseDeviceCode, which bypasses the broker entirely.'
    if ($srcPimGrp.Error -match 'Forbidden|Authorization') {
        # Connected, correct scopes, still refused: the token carries the roles held AT SIGN-IN.
        # Connecting before activating an eligible role - or holding a session from before an
        # activation, or one whose activation has since lapsed - produces exactly this. Scopes
        # look right, the session looks healthy, and every call is refused.
        Write-Host ''
        Write-Host '  Connected but refused. A Graph token carries the roles you held when it was'
        Write-Host '  issued, so a session opened before you activated an eligible role - or one'
        Write-Host '  whose activation has since expired - is refused regardless of its scopes.'
        Write-Host '  Activate the role in PIM, then force a fresh token:'
        Write-Host ''
        Write-Host '    Disconnect-MgGraph'
        Write-Host ''
        Write-Host '  and re-run. Reconnecting is not enough on its own - the existing session is'
        Write-Host '  reused until it is explicitly dropped.'
    }
    Write-Host ''
    Write-Host '  Consequence: permanent group grants are BLOCKED this run. An activated PIM'
    Write-Host '  eligibility is indistinguishable from a standing membership in /memberOf, so'
    Write-Host '  granting one here could hand over permanent access the source only holds on'
    Write-Host '  demand. RBAC and Azure-resource PIM are unaffected.'
}
if ($srcPim.Denied) {
    Write-Section 'AZURE-RESOURCE PIM - PARTIAL'
    Write-Host '  At least one subscription returned Forbidden; that scope is missing from the plan.'
}
if ($adActions.Count) {
    Write-Section 'ON-PREM AD ACTIONS REQUIRED (cannot be done from Azure)'
    foreach ($a in $adActions) { Write-Host "  $a" }
}

# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

if (-not $OutDir) {
    # Deliberately NOT repo-relative. Audit output written inside a working tree leaves
    # untracked files behind and can be discarded by a clean checkout or rebuild - losing the
    # only record of a privileged grant. Local app-data is independent of where the script
    # happens to sit and survives a re-clone.
    $base = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $base) { $base = $HOME }          # non-Windows / unusual profile
    $OutDir = Join-Path $base "PIM-Automation/cadm-clone/$(Get-Date -Format 'yyyy-MM-dd')"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$srcSlug = ($src.userPrincipalName -split '@')[0]
$tgtSlug = ($tgt.userPrincipalName -split '@')[0]
$auditFile = Join-Path $OutDir "clone-$srcSlug-to-$tgtSlug-$stamp.json"
[pscustomobject]@{
    generatedUtc     = (Get-Date).ToUniversalTime().ToString('o')
    applied          = $Apply.IsPresent
    allowRoot        = $AllowRootScope.IsPresent
    pimGroupsReadable = $srcPimGrp.Ok
    source           = @{ id = $src.id; upn = $src.userPrincipalName }
    target           = @{ id = $tgt.id; upn = $tgt.userPrincipalName }
    plan             = $plan
    adActions        = $adActions
} | ConvertTo-Json -Depth 8 | Set-Content -Path $auditFile -Encoding utf8
Write-Host ''
Write-Host "[OK] plan written to $auditFile"

if ($adActions.Count) {
    $adFile = Join-Path $OutDir "ad-actions-$tgtSlug-$stamp.ps1"
    $adActions | Set-Content -Path $adFile -Encoding utf8
    Write-Host "[OK] AD actions written to $adFile (run where the ActiveDirectory module is available)"
}

$todo = @($plan | Where-Object { $_.Action -eq 'CREATE' })
if (-not $Apply) {
    Write-Host ''
    Write-Host "DRY RUN - nothing changed. $($todo.Count) grant(s) would be created."
    Write-Host 'Re-run with -Apply to perform them.'
    return
}
if ($todo.Count -eq 0) { Write-Host ''; Write-Host 'Nothing to do - target already matches.'; return }

# ---------------------------------------------------------------------------
# Interactive selection
# ---------------------------------------------------------------------------
# Placed BEFORE the apply preflights on purpose: those gate on what is actually going to be
# granted ($pimGrpTodo etc.), so an operator who deselects every PIM-GRP row must not be refused
# for lacking a PIM write role they no longer need.
if ($Interactive) {
    Write-Section "INTERACTIVE - select what to clone ($($todo.Count) available)"
    Write-Host '  Everything below CAN be duplicated onto the target. NOTHING is granted until'
    Write-Host '  you select it and confirm. Root-scope rows and PIM-ACTIVE promotions appear'
    Write-Host '  here even though a normal run excludes them by default - read the labels.'
    Write-Host ''
    for ($i = 0; $i -lt $todo.Count; $i++) {
        $t = $todo[$i]
        $mark = if ($t.Scope -eq $RootScope) { '   ** ROOT SCOPE - inherits to the ENTIRE tenant **' } else { '' }
        Write-Host ("  [{0,3}] {1,-7} {2}" -f ($i + 1), $t.Plane, $t.Item)
        Write-Host ("         @ {0}{1}" -f $t.Scope, $mark)
        if ($t.Detail) { Write-Host ("         {0}" -f $t.Detail) }
    }
    Write-Host ''
    while ($true) {
        $raw = Read-Host "Numbers to clone (comma-separated, e.g. 1,4,7), 'all', or blank to cancel"
        if (-not $raw -or -not $raw.Trim()) { Write-Host 'Nothing selected - exiting with no changes.'; exit 0 }
        if ($raw.Trim() -ieq 'all') { break }
        $tokens = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $bad = @($tokens | Where-Object { $_ -notmatch '^\d+$' -or [int]$_ -lt 1 -or [int]$_ -gt $todo.Count })
        if ($bad.Count -or -not $tokens.Count) {
            Write-Host ("  Invalid: {0}. Use numbers 1..{1}, 'all', or blank to cancel." -f ($bad -join ', '), $todo.Count)
            continue
        }
        $pick = @($tokens | ForEach-Object { [int]$_ } | Sort-Object -Unique)
        $todo = @($pick | ForEach-Object { $todo[$_ - 1] })
        break
    }
    Write-Host ("  Selected {0} grant(s) of the above." -f $todo.Count)
}

# ---------------------------------------------------------------------------
# Apply preflight
# ---------------------------------------------------------------------------

# Refuse UP FRONT if the run would write PIM-for-Groups eligibilities without the scope to do
# it. Without this check the RBAC and group grants succeed and every PIM-GRP write fails,
# leaving a half-applied clone: the target holds the standing roles but none of the
# activate-on-demand access, which is the more privileged-looking half. Re-running is safe
# (idempotent), but a partial grant that LOOKS complete is the failure worth preventing.
$pimGrpTodo = @($todo | Where-Object { $_.Plane -eq 'PIM-GRP' })

# Refuse on a DEFINITELY missing directory role for the same reason as the scope check: the
# PIM-GRP writes would fail while everything else landed. 'unknown' is deliberately allowed
# through - the role read can itself be denied, and blocking a legitimate apply on a failed
# lookup is worse than letting Graph return the real error.
#
# -SkipPimRoleCheck relaxes this because the role list is not the only way to hold authority:
# an active group OWNER can write these assignments with no directory role at all, and this
# preflight cannot see ownership. Refusing an owner would repeat the exact mistake that
# excluded Global Administrator from the list for four versions.
if ($pimGrpTodo.Count -and $pimRoleStatus -eq 'missing' -and $SkipPimRoleCheck) {
    Write-Host ''
    Write-Host '  [WARN] no PIM-for-Groups directory role detected, but -SkipPimRoleCheck was'
    Write-Host '         passed - proceeding. Graph will return the real answer per grant.'
}
if ($pimGrpTodo.Count -and $pimRoleStatus -eq 'missing' -and -not $SkipPimRoleCheck) {
    Write-Host ''
    Write-Host "REFUSING TO APPLY: $($pimGrpTodo.Count) PIM-for-Groups grant(s) are planned, but the"
    Write-Host 'signed-in Graph account holds no directory role permitting those writes - they would'
    Write-Host 'all fail while the RBAC grants succeeded, leaving a partial clone.'
    Write-Host ''
    Write-Host ("  roles held:  " + $(if ($script:PimRoleHeld.Count) { $script:PimRoleHeld -join ', ' } else { '(none)' }))
    # Narrow the advice to what will actually work for THESE groups.
    $anyRoleAssignable = $false
    foreach ($it in $pimGrpTodo) {
        if ((Test-GroupRoleAssignable -GroupId $it.Scope) -eq $true) { $anyRoleAssignable = $true }
    }
    if ($anyRoleAssignable) {
        Write-Host "  need one of: Privileged Role Administrator, Global Administrator"
        Write-Host "               (at least one planned group is ROLE-ASSIGNABLE; the other roles"
        Write-Host "                do not carry groupsAssignableToRoles/members/update)"
    } else {
        Write-Host ("  need one of: " + ($PimGroupWriteRoles -join ', '))
    }
    Write-Host '  or:          be an ACTIVE OWNER of the planned group(s) - MS Learn accepts an'
    Write-Host '               owner in place of any directory role, and ownership is scoped to'
    Write-Host '               one group instead of the whole tenant. This check cannot see'
    Write-Host '               ownership, so an owner is refused here; re-run with -SkipPimRoleCheck.'
    Write-Host ''
    Write-Host '  Activate the role in PIM, then:  Disconnect-MgGraph  and re-run.'
    Write-Host '  Or apply only the non-group planes for now:  -SkipGroups'
    exit 2
}

if ($pimGrpTodo.Count -and -not (Test-MgHasScope -Acceptable $MgWriteScopes)) {
    Write-Host ''
    Write-Host "REFUSING TO APPLY: $($pimGrpTodo.Count) PIM-for-Groups grant(s) are planned, but this"
    Write-Host 'Graph session does not hold a write scope, so those would all fail while the'
    Write-Host 'RBAC and group grants succeeded - a partial clone that looks finished.'
    Write-Host ''
    Write-Host ('  scopes held: ' + $(if ($script:MgScopesHeld.Count) { $script:MgScopesHeld -join ', ' } else { '(none)' }))
    Write-Host ("  need one of: " + ($MgWriteScopes -join ', '))
    Write-Host ''
    Write-Host '  Reconnect with write scopes:'
    Write-Host "    Connect-MgGraph -Scopes $MgScopes"
    Write-Host ''
    Write-Host '  Or apply only the non-group planes for now:'
    Write-Host '    -SkipGroups'
    exit 2
}

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

if (-not $Force) {
    Write-Host ''
    Write-Host "About to create $($todo.Count) grant(s) for $($tgt.userPrincipalName)."
    if (($todo | Where-Object { $_.Item -match 'Owner|User Access Administrator' }).Count) {
        Write-Host 'NOTE: this includes Owner and/or User Access Administrator grants.'
    }
    if ((Read-Host 'Type APPLY to continue') -ne 'APPLY') { Write-Host 'Aborted.'; return }
}

$okCount = 0; $failCount = 0
foreach ($item in $todo) {
    switch ($item.Plane) {
        'RBAC' {
            # --role takes the role-definition GUID, not the subscription-prefixed ARM id: the
            # prefix would be wrong for an MG- or root-scoped assignment discovered via a sub.
            $null = Invoke-AzJson -AzArgs @('role', 'assignment', 'create',
                '--assignee-object-id', $tgt.id, '--assignee-principal-type', 'User',
                '--role', $item.Detail, '--scope', $item.Scope, '-o', 'json')
            if ($script:LastAzError) { Write-Host "  [FAIL] RBAC    $($item.Item) @ $($item.Scope): $script:LastAzError"; $failCount++ }
            else { Write-Host "  [OK]   RBAC    $($item.Item) @ $($item.Scope)"; $okCount++ }
        }
        'PIM-RES' {
            # Mirror the source expiration: open-ended stays open-ended, dated keeps its date.
            $srcKey = @($srcPim.Map.Keys | Where-Object {
                $srcPim.Map[$_].Scope -eq $item.Scope -and $srcPim.Map[$_].RoleName -eq $item.Item })[0]
            $e = $srcPim.Map[$srcKey]
            $expiration = if ($e.EndDateTime) { @{ type = 'AfterDateTime'; endDateTime = $e.EndDateTime } }
                          else { @{ type = 'NoExpiration' } }
            $props = [ordered]@{
                principalId      = $tgt.id
                roleDefinitionId = $e.RoleDefinitionId
                requestType      = 'AdminAssign'
                justification    = $Justification
                scheduleInfo     = @{ startDateTime = (Get-Date).ToUniversalTime().ToString('o'); expiration = $expiration }
            }
            if ($TicketNumber -or $TicketSystem) { $props.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
            $bodyFile = Join-Path ([System.IO.Path]::GetTempPath()) "pim-$([guid]::NewGuid()).json"
            (@{ properties = $props } | ConvertTo-Json -Depth 8) | Set-Content -Path $bodyFile -Encoding utf8
            $url = "$ArmBase$($item.Scope)/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$([guid]::NewGuid())?api-version=$PimApi"
            $null = Invoke-Rest -Url $url -Method put -BodyFile $bodyFile
            Remove-Item $bodyFile -ErrorAction SilentlyContinue
            if ($script:LastAzError) { Write-Host "  [FAIL] PIM-RES $($item.Item) @ $($item.Scope): $script:LastAzError"; $failCount++ }
            else { Write-Host "  [OK]   PIM-RES $($item.Item) @ $($item.Scope)"; $okCount++ }
        }
        'PIM-GRP' {
            # A row promoted by -IncludePimActive carries its own AccessId and is NOT in
            # $srcPimGrp.Map - that map holds eligibilities only - so this lookup returns $null
            # for it. Prefer the row's own values and fall back to the map.
            $srcKey = @($srcPimGrp.Map.Keys | Where-Object { $srcPimGrp.Map[$_].GroupId -eq $item.Scope })[0]
            $e = if ($srcKey) { $srcPimGrp.Map[$srcKey] } else { $null }
            $accessId = if ($item.PSObject.Properties['AccessId'] -and $item.AccessId) { $item.AccessId }
                        elseif ($e) { $e.AccessId } else { 'member' }
            # Mirror the source's expiry where there is one. Promoted rows (-IncludePimActive)
            # have none to mirror - the source's ACTIVE assignment is time-bound and often hours
            # from lapsing, so copying its end date would mint an eligibility that expires almost
            # immediately - and they fall through to the group's PIM policy instead of assuming
            # permanent. A policy that forbids permanent eligibility rejects noExpiration with
            #   ExpirationRule - The policy does not allow permanent assignment
            # which is a policy conflict that reads like a tool bug. Validate the policy before applying.
            $expiration = Resolve-PimGroupExpiration -GroupId $item.Scope -AccessId $accessId `
                                                     -EndDateTime $(if ($e) { $e.EndDateTime } else { $null })
            $body = @{
                accessId     = $accessId
                principalId  = $tgt.id
                groupId      = $item.Scope
                action       = 'adminAssign'
                justification = $Justification
                scheduleInfo = @{ startDateTime = (Get-Date).ToUniversalTime().ToString('o'); expiration = $expiration }
            }
            if ($TicketNumber -or $TicketSystem) { $body.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
            $r = Invoke-MgJson -Method POST -Body $body `
                    -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
            if ($r.Ok) { Write-Host "  [OK]   PIM-GRP $($item.Item)"; $okCount++ }
            else { Write-Host "  [FAIL] PIM-GRP $($item.Item): $($r.Error)"; $failCount++ }
        }
        'GROUP' {
            $null = Invoke-AzJson -AzArgs @('ad', 'group', 'member', 'add', '--group', $item.Scope, '--member-id', $tgt.id)
            if ($script:LastAzError) { Write-Host "  [FAIL] GROUP   $($item.Item): $script:LastAzError"; $failCount++ }
            else { Write-Host "  [OK]   GROUP   $($item.Item)"; $okCount++ }
        }
    }
}

Write-Host ''
Write-Host "Copy-CadmAccess done: $okCount granted, $failCount failed. Audit: $auditFile"
if ($adActions.Count) { Write-Host "REMINDER: $($adActions.Count) on-prem group(s) still need the AD script above." }
if ($failCount) { exit 1 }
