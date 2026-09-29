#requires -Version 5.1
# CadmAccess.Core.ps1 - the shared CADM access engine: az/Graph plumbing, session probing,
# principal/group resolvers, RBAC + Azure-resource-PIM + PIM-for-Groups discovery, and the
# progress/reporting helpers. Consumed by Copy-CadmAccess.ps1 and Invoke-CadmAccess.ps1.
#
# DOT-SOURCED, deliberately not a module. The engine and its entry scripts share $script: state
# ($script:LastAzError, $script:MgScopesHeld, ...) and read the callers param variables ($Apply,
# $Interactive, $UseDeviceCode, $ConnectGraph) at call time. Dot-sourcing runs this file in the
# CALLING SCRIPTS scope, so all of that keeps working exactly as it did when this code lived
# inline in Copy-CadmAccess.ps1 (v1.21.0 and earlier). A .psm1 would silently break it: module
# functions resolve $script: against the MODULE scope, and every one of those variables would
# read empty while looking healthy.
#
# Top-level statements here run in the caller too - including the $Interactive override and the
# $MgScopeList computation - so an entry script that never defines those params simply gets the
# defaults.
$CadmCoreVersion = '1.4.0 (2026-08-20)'

$GraphBase = 'https://graph.microsoft.com/v1.0'
$ArmBase   = 'https://management.azure.com'
$PimApi    = '2020-10-01'
$RootScope = '/'
$MgScopes  = ''   # display form, joined from $MgScopeList once that is declared below

$script:LastAzError = ''
$script:AzExe = $null
$script:AzPrefix = @()
$script:MgScopesHeld = @()
$script:MgProbeError = ''
$script:PimManagedGroupIds = $null   # $null = not yet enumerated; @() = enumerated and empty
$script:PimGroupEnumError = ''

# Request only what THIS run needs. A dry run reads; only -Apply writes. Asking for write
# scopes on a report-only run forces every reporting user to hold PIM-for-Groups WRITE consent
# they never exercise - and blocks accounts that legitimately only have read (a Global Reader
# can read this plane fine). Least privilege here decides who can run the tool at all.
$MgReadScopeList = @(
    'PrivilegedEligibilitySchedule.Read.AzureADGroup',
    'PrivilegedAccess.Read.AzureADGroup',
    'Group.Read.All',
    'User.Read.All'
)
$MgWriteScopeList = @(
    'PrivilegedAccess.ReadWrite.AzureADGroup',
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
    'Group.Read.All',
    'User.Read.All'
)
# -Interactive is an APPLY mode by definition - the selection IS what gets granted - so it
# implies -Apply (write scopes, RP preflights, the typed confirmation). It also widens the
# candidate set to everything that CAN be duplicated: root-scope rows and PIM-ACTIVE promotions
# are shown labeled rather than pre-excluded, because the human picking rows one by one IS the
# deliberate decision those exclusions exist to force. Nothing is granted without being selected.
if ($Interactive) {
    if (-not [Environment]::UserInteractive) {
        throw '-Interactive needs an interactive host: it prompts for a selection. Use flag-based runs unattended.'
    }
    $Apply = $true
    $AllowRootScope = $true
    $IncludePimActive = $true
}

$MgScopeList = if ($Apply) { $MgWriteScopeList } else { $MgReadScopeList }
$MgScopes = $MgScopeList -join ','   # display form for the copy-pasteable hints

# Directory roles accepted by the PIM-for-Groups APIs. Source: MS Learn, "Assign eligibility for a
# group in Privileged Identity Management" (Permissions), plus the Graph permission notes on
# "List eligibilityScheduleInstances" / "Create eligibilityScheduleRequest".
#
# GLOBAL ADMINISTRATOR DOES NOT COVER THE READS. The "List eligibilityScheduleInstances" page
# states the signed-in user must own or belong to the group, or hold a supported role: for
# role-assignable groups *Global Reader or Privileged Role Administrator*; for non-role-assignable
# groups Global Reader / Directory Writer / Groups Administrator / Identity Governance
# Administrator / User Administrator. Global Administrator is on neither list.
#
# Cross-principal reads and writes have distinct role requirements. Validate the supported
# role for the exact API operation instead of assuming Global Administrator covers all reads.
#
# v1.13 briefly added GA here on the strength of a DIFFERENT doc - the PIM Permissions section
# naming "Privileged Role Administrator or Global Administrator" for
# microsoft.directory/groupsAssignableToRoles/members/update. That permission governs group
# MEMBERSHIP MANAGEMENT, not these schedule reads. Do not merge the two lists again.
#
# Watch the self-read trap when testing this: any user may read their OWN eligibilities with no
# role and no PIM scope, so signing in AS the source account makes everything look fine.
#
# GA is retained on the WRITE list because the membership-management permission does name it and
# we have not disproved it there - and per the rule this file follows, a preflight refuses only on
# what it can PROVE. Blocking a legitimate apply on a guess is the worse failure; see the
# 'unknown' handling in Get-MgPimRoleStatus.
#
# NOT AN ALLOWLIST OF EVERYTHING THAT WORKS. An active OWNER of the group can read and write its
# PIM assignments holding no directory role at all. That path is not detected here, so an owner
# trips the refusal - pass -SkipPimRoleCheck. See handoff/copy-cadm-access.md.
$PimGroupReadRoles = @(
    'Global Reader',                            # the one that actually unlocks reads
    'Privileged Role Administrator',            # role-assignable groups
    'Directory Writers',                        # the four below cover non-role-assignable groups
    'Groups Administrator',
    'Identity Governance Administrator',
    'User Administrator'
)
$PimGroupWriteRoles = @(
    'Privileged Role Administrator',
    'Global Administrator',                     # documented for membership management; unverified here
    'Directory Writers',
    'Groups Administrator',
    'Identity Governance Administrator',
    'User Administrator'
)

# Either scope in each pair satisfies the requirement (ReadWrite implies Read).
$MgReadScopes  = @('PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAccess.Read.AzureADGroup',
                   'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureADGroup')
$MgWriteScopes = @('PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureADGroup')

# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

function Initialize-AzInvoker {
    # On Windows `az` is az.cmd, which re-invokes python WITHOUT re-quoting its arguments.
    # cmd.exe therefore parses every argument, and the metacharacters '(', ')' and '&' break
    # any Graph/ARM URL that carries an OData filter or more than one query parameter:
    #   $filter=startswith(userPrincipalName,'x')  -> truncated at '(' -> BadRequest about a
    #                                                 missing ')'
    #   ...?api-version=X&$filter=Y                -> split at '&' -> "'$filter' is not
    #                                                 recognized as an internal command"
    # Percent-encoding only fixes the parens; '&' must stay literal to separate parameters,
    # and --uri-parameters double-encodes. The reliable fix is to skip cmd.exe entirely and
    # call the CLI's own python entry point, which PowerShell invokes with proper argv
    # passing. Falls back to plain `az` on non-Windows or an unusual layout.
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCmd) { throw 'az CLI not found on PATH.' }
    if ($azCmd.Source -like '*.cmd') {
        $py = Join-Path (Split-Path (Split-Path $azCmd.Source)) 'python.exe'
        if (Test-Path $py) {
            $script:AzExe = $py
            $script:AzPrefix = @('-IBm', 'azure.cli')
            return
        }
    }
    $script:AzExe = $azCmd.Source
    $script:AzPrefix = @()
}

function Invoke-AzJson {
    # az wrapper returning parsed JSON or $null, never throwing on non-zero exit.
    # $script:LastAzError carries stderr so callers can tell "empty" from "denied" - a 403
    # must be surfaced, not silently rendered as "no assignments".
    param([string[]]$AzArgs)
    $script:LastAzError = ''
    $all = @($script:AzPrefix) + @($AzArgs)
    $stdout = & $script:AzExe @all 2>&1
    if ($LASTEXITCODE -ne 0) {
        $script:LastAzError = ($stdout | Out-String).Trim()
        return $null
    }
    $text = ($stdout | Out-String).Trim()
    if (-not $text) { return $null }
    try { return $text | ConvertFrom-Json }
    catch { $script:LastAzError = "unparseable JSON: $text"; return $null }
}

function Invoke-Rest {
    # URLs are passed through verbatim - Initialize-AzInvoker has already removed cmd.exe from
    # the path, so parens and '&' survive intact. Do NOT percent-encode them here: the python
    # entry point forwards the URL as-is, and Graph rejects a literal '%28' in a filter clause.
    param([string]$Url, [string]$Method = 'get', [string]$BodyFile)
    $a = @('rest', '--method', $Method, '--url', $Url, '--only-show-errors')
    if ($BodyFile) { $a += @('--body', "@$BodyFile") }
    return Invoke-AzJson -AzArgs $a
}

function Write-Section { param([string]$Text) Write-Host ''; Write-Host "=== $Text ===" }

function Test-MgConnected {
    # PIM for Groups needs Graph PowerShell (see .DESCRIPTION). Probe without importing the
    # whole SDK - Microsoft.Graph.Authentication alone provides Get-MgContext/Invoke-MgGraphRequest.
    # Also caches the session's granted scopes, so -Apply can refuse up front rather than
    # discovering mid-run that it cannot write.
    $script:MgScopesHeld = @()
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) { return $false }
        try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop } catch { return $false }
    }
    try {
        $ctx = Get-MgContext
        if (-not $ctx) { return $false }
        if ($ctx.PSObject.Properties['Scopes'] -and $ctx.Scopes) { $script:MgScopesHeld = @($ctx.Scopes) }
        return $true
    } catch { return $false }
}

function Connect-GraphIfNeeded {
    param([string]$ProbePrincipalId)
    # Auto-connect Graph PowerShell when there is no usable session. Default ON because the
    # not-connected path is the one mistake that quietly degrades a run: the PIM-for-Groups
    # plane goes unread, group grants get blocked, and the plan looks smaller than reality.
    #
    # Also reconnects when a session EXISTS but lacks the write scopes - otherwise a read-only
    # session sails through the dry run and -Apply refuses at the last moment. Requesting the
    # write set up front makes one connection serve both.
    #
    # Never throws. An unattended host (or -ConnectGraph:$false) falls through to the normal
    # UNREADABLE reporting rather than hanging on an interactive sign-in that cannot complete.
    if (-not $ConnectGraph) { return }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host '  [SKIP] Microsoft.Graph.Authentication not installed; PIM-for-Groups will be unreadable.'
        Write-Host '         Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        return
    }
    try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop } catch {
        Write-Host "  [SKIP] could not load Microsoft.Graph.Authentication: $($_.Exception.Message)"
        return
    }

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    if ($ctx) {
        # PROBE the existing session rather than trusting its reported scopes. This branch used to
        # accept any session whose (Get-MgContext).Scopes looked right, which is how an operator
        # connecting by hand with the .Read scopes - in a tenant that only consents .ReadWrite -
        # sailed through as "already connected" and then 403'd on every call. Worse, accepting it
        # SKIPPED the broader-scope retry below: the manual connect defeated the workaround
        # written for precisely that tenant. Cost of certainty is one cheap GET.
        [void](Test-MgConnected)   # refresh the reported-scope cache for the diagnostic line
        if (Test-MgPlaneUsable -PrincipalId $ProbePrincipalId) {
            Write-Host "  graph: already connected as $($ctx.Account)"
            return
        }
        Write-Host "  graph: connected as $($ctx.Account), but the session cannot read PIM for Groups."
        if ($script:MgProbeError) { Write-Host "         probe: $($script:MgProbeError)" }
        Write-Host '         Reconnecting.'
        # Do NOT Disconnect-MgGraph here. v1.14 did, and when every reconnect attempt also failed
        # the run ended with NO session at all: Test-MgConnected went false, the `graph roles:` /
        # `graph scopes:` diagnostic lines were skipped entirely, and the UNREADABLE section
        # reported "not loaded / no Get-MgContext session" instead of the actual 403. The
        # diagnostics added to end the guesswork were destroyed by the same change that added
        # them. Connect-MgGraph re-authenticates on its own; keep whatever session exists so the
        # failure can still be described.
    }

    if (-not [Environment]::UserInteractive) {
        Write-Host '  [SKIP] non-interactive host - cannot run an interactive Graph sign-in.'
        Write-Host "         Connect beforehand, or pass -ConnectGraph:`$false to silence this."
        return
    }

    # Try the browser, then fall back to device code AUTOMATICALLY. The browser redirect fails
    # routinely on VDI and locked-down desktops - WAM cannot broker it from an embedded
    # terminal, or the window opens somewhere the user cannot reach - and requiring the
    # operator to know about a flag turns a normal environment into a support call. Falling
    # back costs one extra prompt in the bad case and nothing in the good case.
    # Try least privilege first, then the broader set. Connect-MgGraph does NOT fail when a
    # requested scope is not consented - it connects with whatever it could get, so the session
    # may look healthy and then fail with Forbidden if the requested scopes are unavailable. So verify the token actually carries a usable
    # scope, and re-request with the consented set if not.
    $scopeSets = if ($Apply) { @($MgWriteScopeList) } else { @($MgReadScopeList, $MgWriteScopeList) }
    $attempts = if ($UseDeviceCode) { @($true) } else { @($false, $true) }
    $connected = $false
    for ($si = 0; $si -lt $scopeSets.Count; $si++) {
    $scopeSet = $scopeSets[$si]
    $MgScopeList = $scopeSet
    foreach ($device in $attempts) {
        $how = if ($device) { 'device code - a URL and code will be printed below' }
               else { 'a sign-in window will open' }
        Write-Host "  graph: connecting ($how)..."
        try {
            $cmd = Get-Command Connect-MgGraph
            # Splat optional parameters in only when the installed SDK has them. The
            # device-code switch is spelled differently across builds - 2.36.1 exposes
            # -UseDeviceCode and has no -UseDeviceAuthentication, others are the reverse - so
            # probe for each rather than assuming a version mapping. -NoWelcome is newer-only.
            $p = @{ Scopes = $MgScopeList; ErrorAction = 'Stop' }
            if ($cmd.Parameters.ContainsKey('NoWelcome')) { $p.NoWelcome = $true }
            if ($device) {
                if ($cmd.Parameters.ContainsKey('UseDeviceCode')) { $p.UseDeviceCode = $true }
                elseif ($cmd.Parameters.ContainsKey('UseDeviceAuthentication')) { $p.UseDeviceAuthentication = $true }
                else { Write-Host '  [WARN] this Graph SDK has no device-code parameter; cannot fall back.'; break }
            }
            # NEVER pipe this to Out-Null (or assign it to $null). The device-code flow prints
            # its URL and one-time code through the output stream, so suppressing the stream
            # suppresses the code itself: the user sees "a URL and code will be printed below",
            # no code ever appears, and the sign-in dies 120s later on an inactivity timeout.
            # Any welcome banner is already suppressed by -NoWelcome where the SDK supports it.
            Connect-MgGraph @p
            $ctx = Get-MgContext
            if ($ctx) {
                # Verify with a real call, not with the reported scope list - what was ASKED for
                # is not necessarily what was granted, and the reported list can echo the request.
                [void](Test-MgConnected)
                if (Test-MgPlaneUsable -PrincipalId $ProbePrincipalId) {
                    Write-Host "  graph: connected as $($ctx.Account)"
                    $connected = $true
                } else {
                    Write-Host "  graph: connected as $($ctx.Account) but PIM for Groups is still refused."
                    if ($script:MgProbeError) { Write-Host "         probe: $($script:MgProbeError)" }
                }
                break
            }
        } catch {
            Write-Host "  [WARN] Connect-MgGraph failed: $($_.Exception.Message)"
            if (-not $device) { Write-Host '         Browser sign-in did not complete; retrying with a device code.' }
        }
    }
    if ($connected) { break }
    # Compare by INDEX, never by value. $scopeSet and $scopeSets[-1] are both ARRAYS, and
    # PowerShell's -ne between two arrays FILTERS rather than returning a boolean: it yields the
    # left-hand elements not equal to the right operand, which is a non-empty collection and
    # therefore always TRUTHY. The guard never held, so the session was disconnected even after
    # the final attempt - destroying the `graph roles:` / `graph scopes:` diagnostics and leaving
    # the UNREADABLE section with no session left to describe. Observed as two "Failed to clear
    # the persisted MSAL token cache" warnings on a run with exactly two scope sets.
    if ($si -lt ($scopeSets.Count - 1)) {
        Write-Host '         Retrying with the broader scope set (this tenant may consent only ReadWrite).'
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    }
    if (-not $connected) {
        Write-Host '  [WARN] could not establish a Graph session with a usable PIM-for-Groups scope.'
        Write-Host '         Continuing - PIM for Groups will report UNREADABLE and group grants will be blocked.'
    }
}

function Get-MgPimRoleStatus {
    # Does the SIGNED-IN Graph principal actually hold a directory role that permits
    # PIM-for-Groups writes? Scopes alone are not enough - delegated access is scope AND role -
    # and the usual miss is forgetting to ACTIVATE an eligible role in PIM before connecting.
    # Without this the run gets all the way to -Apply before Graph refuses.
    #
    # Returns 'ok' | 'missing' | 'unknown'. BEST EFFORT: reading /me/transitiveMemberOf can
    # itself be denied, and 'unknown' must never be treated as 'missing' - a false alarm that
    # blocks a legitimate apply is worse than letting Graph deliver the real error.
    $script:PimRoleHeld = @()
    if (-not $script:MgScopesHeld -and -not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) { return 'unknown' }
    $r = Invoke-MgJson -Uri 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName'
    if (-not $r.Ok) { return 'unknown' }
    $names = @($r.Value | ForEach-Object {
        if ($_ -is [hashtable] -and $_.ContainsKey('displayName')) { [string]$_['displayName'] }
        elseif ($_.PSObject.Properties['displayName']) { [string]$_.displayName }
    } | Where-Object { $_ })
    $script:PimRoleHeld = $names
    $accept = if ($Apply) { $PimGroupWriteRoles } else { $PimGroupReadRoles }
    foreach ($n in $names) { if ($accept -contains $n) { return 'ok' } }
    return 'missing'
}

function Test-MgHasScope {
    # True if the session REPORTS any of the acceptable scopes.
    #
    # WEAK EVIDENCE - do not gate a plane on this alone. On several Microsoft.Graph.Authentication
    # builds (Get-MgContext).Scopes returns the scopes REQUESTED at Connect-MgGraph, not the ones
    # the tenant actually granted. A hand-rolled `Connect-MgGraph -Scopes ...Read...` against a
    # tenant that only consents the ReadWrite pair therefore looks healthy here and 403s on first
    # real call. Use Test-MgPlaneUsable for a definitive answer; this survives only to render the
    # "scopes held" diagnostic line and to shape the -Apply scope refusal.
    param([string[]]$Acceptable)
    foreach ($s in $script:MgScopesHeld) {
        if ($Acceptable -contains $s) { return $true }
    }
    return $false
}

function Test-MgPlaneUsable {
    # The only reliable evidence that a Graph session can do this job: make the real call.
    # Scope reporting can be the requested set rather than the granted set, and a directory-role
    # check cannot see consent at all - the two gates are independent and a bare 403 names
    # neither. One cheap GET settles both.
    #
    # Probes with the SOURCE principal, never the signed-in user. Any user may read their OWN PIM
    # eligibilities holding no admin role and no PIM scope - that is how PIM end-users see what
    # they can activate - so a self-probe returns 200 for everybody and proves nothing.
    param([string]$PrincipalId)
    if (-not $PrincipalId) { return $false }
    $base = "$GraphBase/identityGovernance/privilegedAccess/group"
    $r = Invoke-MgJson -Uri "$base/eligibilityScheduleInstances?`$filter=principalId eq '$PrincipalId'"
    if ($r.Ok) { $script:MgProbeError = ''; return $true }
    # By-principal refused does NOT mean the plane is unreadable. Global Reader covers the
    # by-group form and not the directory-wide by-principal sweep, so a session that fails here
    # can still complete the whole job via the per-group fallback. Treat the session as usable if
    # the PIM-group enumeration that fallback depends on succeeds. Failing the probe outright
    # would send a perfectly capable operator away with BLOCKED-PIM-UNKNOWN.
    $script:MgProbeError = $r.Error
    $gid = @(Get-PimCandidateGroupIds -PrincipalId $PrincipalId) | Select-Object -First 1
    if (-not $gid) { return $false }
    $p = Invoke-MgJson -Uri "$base/eligibilityScheduleInstances?`$filter=groupId eq '$gid'"
    if ($p.Ok) { $script:MgProbeError = ''; return $true }
    $script:MgProbeError = "$($r.Error) | by-group: $($p.Error)"
    return $false
}

function Invoke-MgJson {
    # Returns @{ Ok; Value; Error }. Never throws - a denied plane is reported, not fatal.
    param([string]$Uri, [string]$Method = 'GET', [hashtable]$Body)
    try {
        $p = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop' }
        if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10) }
        $r = Invoke-MgGraphRequest @p
        $val = if ($r -and $r.ContainsKey('value')) { @($r.value) } else { @($r) }
        $next = if ($r -and $r.ContainsKey('@odata.nextLink')) { [string]$r['@odata.nextLink'] } else { '' }
        return @{ Ok = $true; Value = $val; Error = ''; Next = $next }
    } catch {
        # The exception message is only the HTTP status ("Forbidden (Forbidden)"), which is
        # useless for diagnosis - it cannot distinguish a missing scope from a missing role from
        # an unsupported query. Graph returns a JSON body carrying errorCode and a real message;
        # dig it out, because two wrong diagnoses were made from the bare status alone.
        $msg = $_.Exception.Message
        $detail = ''
        try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = [string]$_.ErrorDetails.Message } } catch { }
        if (-not $detail) {
            try { $detail = [string]$_.Exception.Response.Content.ReadAsStringAsync().Result } catch { }
        }
        if ($detail) {
            $detail = ($detail -replace '\s+', ' ').Trim()
            # LEAD WITH THE JSON ERROR BODY. The raw text begins with the HTTP status line and a
            # wall of response headers, so a blind truncation spends its whole budget on
            # Transfer-Encoding / Vary / request-id and discards the only useful part. That is
            # exactly how a "PermissionScopeNotGranted" sat unread behind "Forbidden ... x-ms-..."
            # for several rounds of wrong diagnosis. Pull errorCode and the human message out
            # first, and only fall back to the raw blob when neither is present.
            $code = ''
            $m = [regex]::Match($detail, 'errorCode\\?"\s*:\s*\\?"([^"\\]+)')
            if ($m.Success) { $code = $m.Groups[1].Value }
            # Exclude braces so the OUTER message - whose value is itself nested JSON - is skipped
            # in favour of the inner sentence a human can act on.
            $human = ''
            foreach ($mm in [regex]::Matches($detail, 'message\\?"\s*:\s*\\?"([^"\\{}]{15,})')) {
                $t = $mm.Groups[1].Value.Trim()
                if ($t.Length -gt $human.Length) { $human = $t }
            }
            $best = @($code, $human | Where-Object { $_ }) -join ': '
            if ($best) { $detail = $best }
            if ($detail.Length -gt 600) { $detail = $detail.Substring(0, 600) + '...' }
            $msg = "$msg :: $detail"
        }
        return @{ Ok = $false; Value = @(); Error = $msg; Next = '' }
    }
}

function Invoke-MgJsonAll {
    # Invoke-MgJson returns ONE page. Anywhere a short list would be silently wrong - notably the
    # PIM-managed group enumeration, where a missing group means a missing eligibility and a plan
    # that looks complete - follow @odata.nextLink instead.
    param([string]$Uri)
    $all = @(); $next = $Uri; $guard = 0
    while ($next -and $guard -lt 100) {
        $guard++
        $r = Invoke-MgJson -Uri $next
        if (-not $r.Ok) { return @{ Ok = $false; Value = @(); Error = $r.Error } }
        $all += $r.Value
        $next = $r.Next
    }
    return @{ Ok = $true; Value = $all; Error = '' }
}

function Resolve-CadmUser {
    # Accepts objectId, full UPN, or bare prefix. CADM UPN domains are inconsistent, so an
    # exact-UPN miss falls back to a startswith search before giving up.
    param([string]$Ref)
    $sel = 'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled'
    if ($Ref -match '^[0-9a-fA-F-]{36}$') {
        $u = Invoke-Rest -Url "$GraphBase/users/$Ref`?`$select=$sel"
        if ($u) { return $u }
    }
    if ($Ref -like '*@*') {
        $u = Invoke-Rest -Url "$GraphBase/users/$([uri]::EscapeDataString($Ref))`?`$select=$sel"
        if ($u) { return $u }
    }
    $prefix = ($Ref -split '@')[0]
    $r = Invoke-Rest -Url "$GraphBase/users?`$filter=startswith(userPrincipalName,'$prefix')&`$select=$sel"
    $hits = @()
    if ($r -and $r.PSObject.Properties['value']) { $hits = @($r.value) }
    if ($hits.Count -eq 1) { return $hits[0] }
    if ($hits.Count -gt 1) { throw "'$Ref' is ambiguous - matches: $($hits.userPrincipalName -join ', ')" }
    # Include the underlying az error. Every lookup here runs through `az rest`, so the usual
    # cause is not a bad name at all - it is that az has no session (an `az logout`, an expired
    # token, or a failed `az login`). A bare "could not resolve" sends the operator hunting for
    # a typo in a name that is perfectly correct.
    $why = if ($script:LastAzError) { " Last az error: $script:LastAzError" } else { '' }
    $hint = if ($script:LastAzError -match 'az login|not logged in|AADSTS|expired|Please run') {
        " This looks like an az session problem, not a bad name - run: az login --use-device-code"
    } else { '' }
    throw "could not resolve '$Ref'. Checked objectId, exact UPN, and prefix search.$why$hint"
}

function Get-Subscriptions {
    # --refresh is REQUIRED, not an optimisation. The az CLI snapshots the subscription list at
    # login and never updates it on its own, so a machine that logged in before a subscription
    # existed will not see it - the same identity legitimately reports different counts on
    # different machines when their cached subscription inventories differ.
    #
    # This script only scans what az hands it, so a stale cache silently produces a plan that
    # looks complete while missing every grant in the subscriptions it never looked at. On a
    # tool that clones privileged access, a quietly short plan is the worst failure mode.
    $subs = Invoke-AzJson -AzArgs @('account', 'list', '--refresh', '--all', '-o', 'json')
    if (-not $subs) {
        # Refresh needs a live token; fall back rather than failing the whole run, but say so.
        Write-Host "  [WARN] subscription refresh failed ($script:LastAzError); using the cached list."
        $subs = Invoke-AzJson -AzArgs @('account', 'list', '--all', '-o', 'json')
    }
    if (-not $subs) { throw "could not list subscriptions ($script:LastAzError)" }
    return @($subs | ForEach-Object { [pscustomobject]@{ Id = $_.id; Name = $_.name } })
}

function Get-RoleDefGuid {
    # ARM returns roleDefinitionId prefixed with the subscription the query ran against, e.g.
    # /subscriptions/<queried-sub>/providers/Microsoft.Authorization/roleDefinitions/<guid>.
    # A single root- or MG-scoped assignment therefore yields a DIFFERENT roleDefinitionId for
    # every subscription scanned. Keying on the raw string can duplicate inherited grants and
    # would have made the target-exists check miss. The trailing GUID is the stable identity.
    param([string]$RoleDefinitionId)
    if (-not $RoleDefinitionId) { return '' }
    return ($RoleDefinitionId -split '/')[-1].ToLower()
}

function Start-Phase {
    # The scan makes several calls per subscription. Show progress during long inventories.
    param([string]$Label)
    Write-Host -NoNewline "  $Label "
}
function Step-Phase { Write-Host -NoNewline '.' }
function End-Phase   { param([string]$Note = '') Write-Host " done$Note" }

function Get-RoleAssignmentsFor {
    # Direct + inherited + group-derived, deduped on (roleDefinitionGuid, scope, principalId).
    # Each record carries its TRUE scope, so an MG-level grant surfaces once with the MG scope
    # even though it is discovered by querying a subscription underneath it.
    param([string]$PrincipalId, [object[]]$Subs, [string]$Label = 'role assignments')
    $map = [ordered]@{}
    Start-Phase $Label
    foreach ($s in $Subs) {
        Step-Phase
        $rows = Invoke-AzJson -AzArgs @('role', 'assignment', 'list', '--assignee', $PrincipalId,
            '--subscription', $s.Id, '--all', '--include-inherited', '--include-groups', '-o', 'json')
        if (-not $rows) { continue }
        foreach ($r in $rows) {
            $key = "$(Get-RoleDefGuid $r.roleDefinitionId)|$($r.scope)|$($r.principalId)".ToLower()
            if (-not $map.Contains($key)) { $map[$key] = $r }
        }
    }
    End-Phase
    return $map
}

function Get-PimResourceFor {
    param([string]$PrincipalId, [object[]]$Subs, [string]$Label = 'PIM eligibilities')
    $map = [ordered]@{}; $denied = $false
    Start-Phase $Label
    foreach ($s in $Subs) {
        Step-Phase
        $url = "$ArmBase/subscriptions/$($s.Id)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances" +
               "?api-version=$PimApi&`$filter=principalId eq '$PrincipalId'"
        $r = Invoke-Rest -Url $url
        if (-not $r) {
            if ($script:LastAzError -match 'Forbidden|AuthorizationFailed') { $denied = $true }
            continue
        }
        foreach ($v in @($r.value)) {
            $p = $v.properties; $ep = $p.expandedProperties
            # Same subscription-prefix normalisation as Get-RoleAssignmentsFor - and here the
            # key doubles as the source-vs-target comparison key, so it must not carry a
            # principalId either.
            $key = "$(Get-RoleDefGuid $p.roleDefinitionId)|$($ep.scope.id)".ToLower()
            if (-not $map.Contains($key)) {
                $map[$key] = [pscustomobject]@{
                    RoleDefinitionId = $p.roleDefinitionId
                    RoleName         = $ep.roleDefinition.displayName
                    Scope            = $ep.scope.id
                    EndDateTime      = $p.endDateTime
                }
            }
        }
    }
    End-Phase
    return @{ Map = $map; Denied = $denied }
}

function Get-PimActivatedFor {
    # Azure-resource role assignments that are CURRENTLY ACTIVATED through PIM, i.e. temporary
    # elevation the principal switched on and that expires on its own.
    #
    # This matters because `az role assignment list` cannot tell them apart from standing
    # grants - an activation materialises as an ordinary roleAssignment for its lifetime. Left
    # unfiltered, cloning an operator who happened to be elevated at the time converts their
    # temporary elevation into PERMANENT access for the target. assignmentType distinguishes them: 'Activated' vs 'Assigned'.
    param([string]$PrincipalId, [object[]]$Subs, [string]$Label = 'active PIM elevations')
    $map = [ordered]@{}; $denied = $false
    Start-Phase $Label
    foreach ($s in $Subs) {
        Step-Phase
        $url = "$ArmBase/subscriptions/$($s.Id)/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" +
               "?api-version=$PimApi&`$filter=principalId eq '$PrincipalId'"
        $r = Invoke-Rest -Url $url
        if (-not $r) {
            if ($script:LastAzError -match 'Forbidden|AuthorizationFailed') { $denied = $true }
            continue
        }
        foreach ($v in @($r.value)) {
            $p = $v.properties
            if ($p.assignmentType -ne 'Activated') { continue }   # 'Assigned' is standing access
            $ep = $p.expandedProperties
            $key = "$(Get-RoleDefGuid $p.roleDefinitionId)|$($ep.scope.id)".ToLower()
            if (-not $map.Contains($key)) {
                $map[$key] = [pscustomobject]@{
                    RoleName = $ep.roleDefinition.displayName
                    Scope    = $ep.scope.id
                    EndsAt   = $p.endDateTime
                }
            }
        }
    }
    End-Phase
    return @{ Map = $map; Denied = $denied }
}

function Get-PimCandidateGroupIds {
    # Groups worth asking the PIM plane about.
    #
    # THERE IS NO API THAT LISTS PIM-ONBOARDED GROUPS. roleManagementPolicies requires BOTH
    # scopeId AND scopeType, and scopeId must name one specific group - trying to enumerate with
    # `?$filter=scopeType eq 'Group'` returns "BadRequest :: The required parameters ScopeId is
    # missing". So the candidate set has to be built from the group list instead.
    #
    # Two sources, unioned:
    #   1. role-assignable groups - server-filterable, capped at 500 per tenant by Entra, and the
    #      privileged groups a clone actually cares about.
    #   2. the principal's own groups - catches non-role-assignable PIM groups it belongs to.
    #
    # Source 1 is what makes this work at all: the candidate list CANNOT come from /memberOf
    # alone, because a PIM-*eligible* member is not a member until they activate, so /memberOf
    # omits exactly the eligibilities this plane exists to find.
    #
    # Dynamic and on-prem-synced groups are dropped - MS Learn states neither can be managed in
    # PIM for Groups, so querying them is pure throttle risk. Per MS Learn these APIs may be
    # called for groups that are not onboarded to PIM; the guidance is only to avoid it where
    # possible, to reduce throttling.
    #
    # Cached per run. Uses the az plane, so it works before any Graph session exists.
    param([string]$PrincipalId)
    if ($null -ne $script:PimManagedGroupIds) { return $script:PimManagedGroupIds }
    $ids = [ordered]@{}
    $keep = {
        param($g)
        if (-not $g) { return }
        if ($g.onPremisesSyncEnabled) { return }
        if ($g.groupTypes -and (@($g.groupTypes) -contains 'DynamicMembership')) { return }
        if ($g.id) { $ids[[string]$g.id] = $true }
    }
    $ra = Invoke-Rest -Url ("$GraphBase/groups?`$filter=isAssignableToRole eq true" +
                            "&`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999")
    if ($ra) { foreach ($g in @($ra.value)) { & $keep $g } }
    else { $script:PimGroupEnumError = "role-assignable group list failed: $script:LastAzError" }

    if ($PrincipalId) {
        $mine = Invoke-Rest -Url ("$GraphBase/users/$PrincipalId/memberOf/microsoft.graph.group" +
                                  "?`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999")
        if ($mine) { foreach ($g in @($mine.value)) { & $keep $g } }
    }
    $script:PimManagedGroupIds = @($ids.Keys)
    # ALWAYS return via @(...) at the call site too - `return @()` from a PowerShell function
    # unrolls to nothing, so the caller receives $null and `.Count` throws
    # "The property 'Count' cannot be found on this object".
    return $script:PimManagedGroupIds
}

function Get-PimGroupsFor {
    # PIM for Groups: eligibilities AND currently-active PIM assignments. Both matter - an
    # ACTIVE one means the principal has activated an eligibility, which also materialises in
    # /memberOf and must not be mistaken for a standing membership.
    #
    # TWO QUERY SHAPES, and they do NOT carry the same authorization.
    #
    # `$filter=principalId eq ...` is a directory-wide sweep across every PIM-managed group.
    # `$filter=groupId eq ...` is scoped to one group and is the documented administrator path.
    # A caller authorized for group-scoped reads may still be refused a directory-wide query.
    #
    # So: try by-principal once (one call, and it works for a caller who does hold the
    # directory-wide permission), and fan out per group only when it is refused.
    param([string]$PrincipalId)
    $out = [ordered]@{}; $active = @{}
    $base = "$GraphBase/identityGovernance/privilegedAccess/group"

    $elig = Invoke-MgJsonAll -Uri "$base/eligibilityScheduleInstances?`$filter=principalId eq '$PrincipalId'"
    $asgV = @()
    if ($elig.Ok) {
        $eligV = $elig.Value
        $a = Invoke-MgJsonAll -Uri "$base/assignmentScheduleInstances?`$filter=principalId eq '$PrincipalId'"
        if ($a.Ok) { $asgV = $a.Value }
    } else {
        # @(...) is load-bearing: `return @()` from a PowerShell function unrolls to nothing, so
        # an empty result arrives as $null and $groupIds.Count throws.
        $groupIds = @(Get-PimCandidateGroupIds -PrincipalId $PrincipalId)
        if (-not $groupIds.Count) {
            # Nothing to fall back to - report the ORIGINAL by-principal error, plus why the
            # fallback could not run, rather than a bare "no groups".
            $why = if ($script:PimGroupEnumError) { " (group enumeration also failed: $script:PimGroupEnumError)" } else { '' }
            return @{ Ok = $false; Error = "$($elig.Error)$why"; Map = $out; ActiveGroupIds = @() }
        }
        Start-Phase "PIM groups (per-group, $($groupIds.Count))"
        $eligV = @(); $failed = 0; $lastErr = ''
        foreach ($gid in $groupIds) {
            Step-Phase
            $e = Invoke-MgJsonAll -Uri "$base/eligibilityScheduleInstances?`$filter=groupId eq '$gid'"
            if (-not $e.Ok) { $failed++; $lastErr = $e.Error; continue }
            $eligV += @($e.Value)
            $a = Invoke-MgJsonAll -Uri "$base/assignmentScheduleInstances?`$filter=groupId eq '$gid'"
            if ($a.Ok) { $asgV += @($a.Value) }
        }
        End-Phase
        # A partial sweep must not pass as a complete read. Silently dropping groups here would
        # under-report eligibilities, and an under-reported PIM plane is what BLOCKED-PIM-UNKNOWN
        # exists to prevent.
        if ($failed -eq $groupIds.Count) {
            return @{ Ok = $false; Error = "per-group fallback failed for all $failed group(s): $lastErr"; Map = $out; ActiveGroupIds = @() }
        }
        if ($failed) {
            return @{ Ok = $false; Error = "per-group fallback incomplete - $failed of $($groupIds.Count) group(s) unreadable: $lastErr"; Map = $out; ActiveGroupIds = @() }
        }
    }

    foreach ($e in $eligV) {
        if ([string]$e.principalId -ne $PrincipalId) { continue }   # by-group returns every principal
        $key = "$($e.groupId)|$($e.accessId)"
        if (-not $out.Contains($key)) {
            $out[$key] = [pscustomobject]@{
                GroupId = $e.groupId; AccessId = $e.accessId
                EndDateTime = $(if ($e.ContainsKey('endDateTime')) { $e.endDateTime } else { $null })
            }
        }
    }
    foreach ($a in $asgV) {
        if ([string]$a.principalId -ne $PrincipalId) { continue }
        # Keep the accessId, not just a flag: -IncludePimActive needs it to re-create the access
        # as an eligibility, and member-vs-owner is not guessable.
        $active[$a.groupId] = [string]$a.accessId
    }
    return @{ Ok = $true; Error = ''; Map = $out; ActiveGroupIds = @($active.Keys); ActiveMap = $active }
}

function Get-PimGroupExpirationRule {
    # The group's PIM policy rule governing ADMIN-ASSIGNED ELIGIBILITY duration.
    # Returns @{ Required; MaxDuration } or $null when it cannot be read.
    #
    # Needed because a PIM policy may forbid permanent eligibility. Posting a noExpiration
    # request against such a group fails with:
    #   BadRequest :: The following policy rules failed: ExpirationRule - The policy does not
    #   allow permanent assignment
    # which is a POLICY conflict, not a permissions problem, and reads like a tool bug.
    #
    # Graph-only: the az CLI first-party app lacks RoleManagementPolicy.Read.AzureADGroup, so
    # this must go through the Microsoft Graph PowerShell session like the rest of this plane.
    param([string]$GroupId, [string]$AccessId = 'member')
    $uri = "$GraphBase/policies/roleManagementPolicyAssignments" +
           "?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq '$AccessId'" +
           "&`$expand=policy(`$expand=rules)"
    $r = Invoke-MgJson -Uri $uri
    if (-not $r.Ok) { return $null }
    foreach ($pa in $r.Value) {
        $policy = if ($pa -is [hashtable] -and $pa.ContainsKey('policy')) { $pa['policy'] }
                  elseif ($pa.PSObject.Properties['policy']) { $pa.policy } else { $null }
        if (-not $policy) { continue }
        $rules = if ($policy -is [hashtable] -and $policy.ContainsKey('rules')) { $policy['rules'] }
                 elseif ($policy.PSObject.Properties['rules']) { $policy.rules } else { @() }
        foreach ($rule in @($rules)) {
            $id = if ($rule -is [hashtable]) { [string]$rule['id'] } else { [string]$rule.id }
            # Admin-assigned ELIGIBILITY, not activation and not admin-assignment.
            if ($id -ne 'Expiration_Admin_Eligibility') { continue }
            # isExpirationRequired is deliberately NOT read. It only answers "may this be
            # permanent?", and since v1.2.0 nothing here grants permanent eligibility under any
            # circumstances - so the answer cannot change the outcome. Only the ceiling matters.
            # It was returned as a Required field until v1.3.0, where it sat unread.
            $max = if ($rule -is [hashtable]) { [string]$rule['maximumDuration'] } else { [string]$rule.maximumDuration }
            return @{ MaxDuration = $max }
        }
    }
    return $null
}

function ConvertTo-CadmTimeSpan {
    # ISO-8601 duration -> TimeSpan, or $null when it cannot be parsed.
    #
    # XmlConvert also handles the CALENDAR forms PIM actually emits, normalising them to fixed
    # lengths: P1Y -> 365d, P6M -> 180d, P1M -> 30d. Verified 2026-08-19; an earlier version of
    # this comment claimed it threw on those, which was wrong. The normalisation is an
    # approximation, but it is only ever used to decide whether our default exceeds a policy
    # ceiling - and on that question a 365/360-day year never changes the answer.
    #
    # Only genuine garbage throws. $null therefore means "unparseable", never "zero".
    param([string]$Iso)
    if (-not $Iso) { return $null }
    try { return [System.Xml.XmlConvert]::ToTimeSpan($Iso) } catch { return $null }
}

function Resolve-PimGroupExpiration {
    # Pick an expiration the group's PIM policy will actually accept, in precedence order:
    #   1. an explicit Duration (a profile pinning a term)
    #   2. an explicit EndDateTime (the clone path mirroring the source's expiry)
    #   3. the group policy's maximum, when our default would exceed it
    #   4. the default term - ONE YEAR
    #
    # NEVER noExpiration. Permanent eligibility is refused outright by any policy with
    #   ExpirationRule - The policy does not allow permanent assignment
    # and is in any case the drift-shaped default this toolchain exists to remove. A bounded
    # eligibility that has to be renewed is the safer failure: access lapses rather than
    # accumulating silently.
    #
    # The clamp in step 3 matters as much as reading the policy at all. Sending a year at a group
    # capped lower fails with a DIFFERENT ExpirationRule error, so "read the policy" without
    # "respect its ceiling" just trades one BadRequest for another. An unparseable ceiling is
    # used verbatim - deferring to the group's own configuration is always safe.
    param(
        [string]$GroupId,
        [string]$AccessId = 'member',
        [string]$EndDateTime,
        [string]$Duration,
        [string]$DefaultDuration = 'P365D'
    )
    if ($Duration)    { return @{ type = 'afterDuration'; duration = $Duration } }
    if ($EndDateTime) { return @{ type = 'afterDateTime'; endDateTime = $EndDateTime } }

    $rule = Get-PimGroupExpirationRule -GroupId $GroupId -AccessId $AccessId
    return @{ type = 'afterDuration'; duration = (Select-CadmDuration -MaxDuration $rule.MaxDuration -DefaultDuration $DefaultDuration) }
}

function Select-CadmDuration {
    # The default term, clamped to a policy ceiling. Shared by every PIM plane so the clamp
    # cannot drift between them.
    #
    # No ceiling (or an unreadable policy - commonly a missing RoleManagementPolicy.Read scope)
    # takes the default; if the target turns out to be stricter the API says so plainly. An
    # unparseable ceiling is used verbatim, because deferring to the policy's own configuration
    # is always safe.
    param([string]$MaxDuration, [string]$DefaultDuration = 'P365D')
    if (-not $MaxDuration) { return $DefaultDuration }
    $maxTs = ConvertTo-CadmTimeSpan $MaxDuration
    $defTs = ConvertTo-CadmTimeSpan $DefaultDuration
    if (-not $maxTs -or -not $defTs) { return $MaxDuration }
    if ($defTs -gt $maxTs)           { return $MaxDuration }
    return $DefaultDuration
}

# ---------------------------------------------------------------------------
# PIM for Entra DIRECTORY ROLES - a different plane from PIM for Groups
# ---------------------------------------------------------------------------
# Distinct API surface (roleManagement/directory/*), distinct scope family
# (*.Directory rather than *.AzureADGroup), and distinct consent. A tenant consented for the
# group plane is NOT automatically consented for directory-role operations. Scopes are requested only when a profile actually needs them, so group-only work
# does not drag Directory consent along with it.
# Two different jobs, following the same *ScopeList / *Scopes split as the group plane:
#   ...ScopeList - what to REQUEST at Connect-MgGraph. Least privilege, so the write set asks
#                  for RoleManagementPolicy.READ (reading a ceiling never needs write).
#   ...Scopes    - what SATISFIES the gate. Broader, because an operator may already hold the
#                  wider RoleManagement.ReadWrite.Directory, which subsumes the eligibility
#                  write; refusing them for not holding the narrower name would be wrong.
$MgDirReadScopeList  = @('RoleEligibilitySchedule.Read.Directory', 'RoleManagementPolicy.Read.Directory')
$MgDirWriteScopeList = @('RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagementPolicy.Read.Directory')
$MgDirWriteScopes    = @('RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagement.ReadWrite.Directory')

function Resolve-DirectoryRoleId {
    # Directory role NAME -> roleDefinitionId. Profiles name roles for readability; the API wants
    # the GUID. Returns @{ Ok; Id; Error }.
    #
    # Two failures that must NOT be conflated:
    #   * the plane is UNREADABLE (no Graph session, missing scope) - not fatal. The caller
    #     degrades to BLOCKED-PIM-UNKNOWN, matching every other plane; a dry run on a host with
    #     no Graph session must still print a plan rather than dying with a stack trace.
    #   * the role NAME is wrong or ambiguous - fatal, and thrown here. That is a profile
    #     authoring bug, and reporting it as "unknown" would hide a typo behind a scope warning.
    param([string]$Name)
    $r = Invoke-MgJson -Uri ("$GraphBase/roleManagement/directory/roleDefinitions" +
                             "?`$filter=displayName eq '$($Name -replace "'","''")'")
    if (-not $r.Ok) { return @{ Ok = $false; Id = ''; Error = $r.Error } }
    $hits = @($r.Value)
    if ($hits.Count -eq 0) { throw "directory role '$Name' not found - check the profile spelling." }
    if ($hits.Count -gt 1) { throw "directory role '$Name' is ambiguous ($($hits.Count) matches)." }
    $h = $hits[0]
    $id = if ($h -is [hashtable]) { [string]$h['id'] } else { [string]$h.id }
    return @{ Ok = $true; Id = $id; Error = '' }
}

function Get-DirRoleEligibilitiesFor {
    # Existing DIRECTORY-ROLE eligibilities for a principal, keyed roleDefinitionId|directoryScopeId.
    # Returns @{ Ok; Map; Error } - Ok=$false means UNREADABLE, which must never be treated as
    # "has none". Same discipline as the group plane: a blind spot is reported, not assumed away.
    param([string]$PrincipalId)
    $map = @{}
    $r = Invoke-MgJsonAll -Uri ("$GraphBase/roleManagement/directory/roleEligibilityScheduleInstances" +
                                "?`$filter=principalId eq '$PrincipalId'")
    if (-not $r.Ok) { return @{ Ok = $false; Map = $map; Error = $r.Error } }
    foreach ($e in $r.Value) {
        $rid = if ($e -is [hashtable]) { [string]$e['roleDefinitionId'] } else { [string]$e.roleDefinitionId }
        $ds  = if ($e -is [hashtable]) { [string]$e['directoryScopeId'] } else { [string]$e.directoryScopeId }
        if ($rid) { $map["$rid|$ds".ToLower()] = $true }
    }
    return @{ Ok = $true; Map = $map; Error = '' }
}

function Get-DirRoleExpirationRule {
    # Expiration_Admin_Eligibility for a DIRECTORY role - how long an admin-assigned eligibility
    # may last. Not the activation duration, and not the same policy as the group plane.
    param([string]$RoleDefinitionId)
    $uri = "$GraphBase/policies/roleManagementPolicyAssignments" +
           "?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'" +
           "&`$expand=policy(`$expand=rules)"
    $r = Invoke-MgJson -Uri $uri
    if (-not $r.Ok) { return $null }
    foreach ($pa in $r.Value) {
        $policy = if ($pa -is [hashtable] -and $pa.ContainsKey('policy')) { $pa['policy'] }
                  elseif ($pa.PSObject.Properties['policy']) { $pa.policy } else { $null }
        if (-not $policy) { continue }
        $rules = if ($policy -is [hashtable] -and $policy.ContainsKey('rules')) { $policy['rules'] }
                 elseif ($policy.PSObject.Properties['rules']) { $policy.rules } else { @() }
        foreach ($rule in @($rules)) {
            $id = if ($rule -is [hashtable]) { [string]$rule['id'] } else { [string]$rule.id }
            if ($id -ne 'Expiration_Admin_Eligibility') { continue }
            $max = if ($rule -is [hashtable]) { [string]$rule['maximumDuration'] } else { [string]$rule.maximumDuration }
            return @{ MaxDuration = $max }
        }
    }
    return $null
}

function Get-GroupsFor {
    param([string]$PrincipalId)
    $r = Invoke-Rest -Url ("$GraphBase/users/$PrincipalId/memberOf/microsoft.graph.group" +
                           "?`$select=id,displayName,onPremisesSyncEnabled,securityEnabled&`$top=999")
    if (-not $r) { return @() }
    return @($r.value)
}

function Test-GroupRoleAssignable {
    # Role-assignable groups narrow the acceptable roles to Privileged Role Administrator or
    # Global Administrator. The other four - Directory Writers, Groups Administrator, Identity
    # Governance Administrator, User Administrator - apply only to non-role-assignable groups.
    # Listing all six regardless would send an operator off to assign a role that still cannot
    # make the call. $null when it cannot be determined, so the caller can stay vague rather
    # than wrong.
    param([string]$GroupId)
    $g = Invoke-Rest -Url "$GraphBase/groups/$GroupId`?`$select=isAssignableToRole"
    if ($g -and $g.PSObject.Properties['isAssignableToRole']) { return [bool]$g.isAssignableToRole }
    return $null
}

function Get-GroupName {
    param([string]$GroupId)
    $g = Invoke-Rest -Url "$GraphBase/groups/$GroupId`?`$select=displayName"
    if ($g -and $g.PSObject.Properties['displayName']) { return $g.displayName }
    return $GroupId
}

