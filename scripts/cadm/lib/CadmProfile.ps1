#requires -Version 5.1

# CadmProfile.ps1 - tenant binding, profile loading, and the profile-apply grant path for the
# CADM access tooling. Dot-sourced by Invoke-CadmAccess.ps1, which dot-sources CadmAccess.Core.ps1
# FIRST - this file calls the engine's plumbing (Invoke-AzJson, Resolve-CadmUser,
# Get-RoleAssignmentsFor, Get-GroupsFor, Get-PimGroupsFor, Invoke-MgJson, $script:LastAzError).
#
# Kept OFF the clone grant loop on purpose. A profile item is declarative - literal role, scope
# and accessId - so it needs none of the source-diff machinery, promoted-row handling or
# expiration-mirroring the clone path carries. A separate, smaller grant path means adding
# profiles cannot regress the field-tested clone behaviour (its pinned tests).

$CadmProfileVersion = '1.5.0 (2026-09-29)'

function Import-CadmTenant {
    # Match the CURRENT az login's tenantId against scripts/cadm/tenants/*/tenant.psd1 and return
    # the matching binding. This is the guardrail that makes the tooling safe to carry between
    # customers: profiles from one tenant can never be applied inside another's, because a run
    # with no matching tenant file is refused before anything is read.
    param([string]$TenantsDir)
    $acct = Invoke-AzJson -AzArgs @('account', 'show', '-o', 'json')
    if (-not $acct) { throw "no active az session ($script:LastAzError). Run: az login" }
    $liveTid = [string]$acct.tenantId
    $files = @(Get-ChildItem -Path $TenantsDir -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'tenant.psd1' } | Where-Object { Test-Path $_ })
    foreach ($f in $files) {
        $t = Import-PowerShellDataFile -Path $f
        if ([string]$t.TenantId -ieq $liveTid) {
            Set-CadmTenant -TenantId $t.TenantId
            $t.Path = $f
            $t.ProfilesDir = Join-Path (Split-Path $f) 'profiles'
            return $t
        }
    }
    $known = @($files | ForEach-Object { (Import-PowerShellDataFile -Path $_).TenantId }) -join ', '
    throw ("no tenant binding for the signed-in tenant $liveTid. " +
           "Known: $(if ($known) { $known } else { '(none)' }). " +
           "Add scripts/cadm/tenants/<name>/tenant.psd1 with a matching TenantId, or `az login` to the right tenant.")
}

function Get-CadmProfiles {
    # Every *.psd1 under the tenant's profiles/ dir, as @{ Key; Name; Description; Path; Data }.
    # Key is the file basename - the stable id an operator passes to -Profile.
    param([string]$ProfilesDir)
    $out = @()
    foreach ($f in @(Get-ChildItem -Path $ProfilesDir -Filter '*.psd1' -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $d = Import-PowerShellDataFile -Path $f.FullName
        $out += [pscustomobject]@{
            Key = $f.BaseName; Name = [string]$d.Name; Description = [string]$d.Description
            Path = $f.FullName; Data = $d
        }
    }
    return $out
}

function Get-ProfileEntries {
    # @($null) is a ONE-ELEMENT array in PowerShell, not an empty one. A profile that simply omits
    # an optional key therefore yields a single $null entry, and every loop over it processes that
    # $null as a malformed record - "a DirectoryRoleEligibilities entry has no Role" thrown at a
    # profile that never mentioned the key. `.Count -gt 0` lies the same way.
    #
    # Adding the DirectoryRoleEligibilities plane broke three of four shipped profiles exactly
    # this way. Every read of a profile collection goes through here so a new optional key cannot
    # repeat it.
    param($Value)
    return @($Value | Where-Object { $null -ne $_ })
}

function Assert-ProfileSafe {
    # A profile must not be able to express the very drift this tooling exists to remove. Standing
    # Owner / User Access Administrator, root-scope '/', and permanent membership of a PIM-managed
    # or role-assignable group are all refused HERE, so the policy lives once rather than relying
    # on template authors to remember it. Throws on the first violation.
    param([object]$Profile, [hashtable]$Tenant)
    $name = $Profile.Name
    foreach ($r in (Get-ProfileEntries $Profile.Data.Rbac)) {
        $role = [string]$r.Role
        $scope = Resolve-CadmScope -Scope ([string]$r.Scope) -Tenant $Tenant
        if ($role.Trim() -in @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator') -or
            (Get-RoleDefGuid $role.Trim()) -in @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')) {
            throw "profile '$name': standing '$role' is not allowed - grant it just-in-time via a PIM-for-Groups eligibility instead."
        }
        if ($scope -eq '/' -or $scope -eq $RootScope) {
            throw "profile '$name': root scope '/' is never allowed in a profile."
        }
        if (-not $r.ContainsKey('Role') -or -not $r.ContainsKey('Scope')) {
            throw "profile '$name': every Rbac entry needs Role and Scope."
        }
    }
    foreach ($g in (Get-ProfileEntries $Profile.Data.GroupMemberships)) {
        if (-not $g.Group) { throw "profile '$name': a GroupMemberships entry has no Group." }
    }
    foreach ($e in (Get-ProfileEntries $Profile.Data.PimGroupEligibilities)) {
        if (-not $e.Group) { throw "profile '$name': a PimGroupEligibilities entry has no Group." }
        $acc = [string]$e.AccessId
        if ($acc -and $acc -notin @('member', 'owner')) {
            throw "profile '$name': PimGroupEligibilities AccessId must be 'member' or 'owner', got '$acc'."
        }
    }
    # DIRECTORY-ROLE eligibilities. There is deliberately NO key for a standing directory role:
    # this plane can only ever make someone ELIGIBLE. Global Administrator is permitted here and
    # nowhere else - as a JIT eligibility it is Microsoft's recommended pattern, whereas a
    # standing one is the single most dangerous grant in a tenant.
    foreach ($d in (Get-ProfileEntries $Profile.Data.DirectoryRoleEligibilities)) {
        if (-not $d.Role) { throw "profile '$name': a DirectoryRoleEligibilities entry has no Role." }
        $ds = [string]$d.DirectoryScopeId
        if ($ds -and $ds -ne '/') {
            throw "profile '$name': DirectoryRoleEligibilities DirectoryScopeId must be '/' (tenant) - administrative-unit scoping is not supported here."
        }
    }
    if ($Profile.Data.Keys -contains 'DirectoryRoles') {
        throw "profile '$name': 'DirectoryRoles' would grant STANDING directory roles and is not supported. Use DirectoryRoleEligibilities."
    }
}

function Resolve-CadmScope {
    param([string]$Scope, [hashtable]$Tenant)
    if ((Get-CadmField $Tenant 'ScopeTokens') -and $Tenant.ScopeTokens.ContainsKey($Scope)) { $Scope = [string]$Tenant.ScopeTokens[$Scope] }
    if ($Scope -eq '/') { throw "root scope '/' is not allowed." }
    # Reject ambiguous URI representations before any cloud lookup or write.
    if ($Scope -match '[%?#\\\s]' -or $Scope -match '//|/(\.|\.\.)(/|$)' -or $Scope.EndsWith('/')) {
        throw 'Non-canonical ARM scope is not allowed.'
    }
    if ($Scope -match '^/subscriptions/[0-9a-fA-F-]{36}(?:/resourceGroups/[^/]+(?:/providers/[^/]+(?:/[^/]+/[^/]+)+)?)?$' -or
        $Scope -match '^/providers/Microsoft.Management/managementGroups/[^/]+$') { return $Scope }
    throw "unresolved scope '$Scope' - use a canonical subscription, resource, or management-group scope."
}

function Resolve-CadmStandingRole {
    param([string]$Role, [string]$Scope)
    Assert-CadmScopeTenant -Scope $Scope
    $defs = @(Invoke-AzJson -AzArgs @('role', 'definition', 'list', '--name', $Role.Trim(), '--scope', $Scope, '-o', 'json'))
    if ($script:LastAzError -or $defs.Count -ne 1 -or $null -eq $defs[0]) { throw 'Cannot uniquely resolve standing role definition.' }
    $def = $defs[0]
    $id = Get-RoleDefGuid ([string](Get-CadmField $def 'id'))
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($id, [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Role definition has no canonical ID.' }
    if ($id -in @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')) {
        throw 'Privileged role cannot be assigned standing by a profile.'
    }
    $permissions = @(Get-CadmField $def 'permissions')
    if (-not $permissions.Count -or $null -eq $permissions[0]) { throw 'Role permissions are unreadable.' }
    # Custom role semantics can change after preview. Only provably read-only custom
    # roles are supported, and definitions are re-read immediately before each grant.
    $type = [string](Get-CadmField $def 'roleType')
    if ($type -notin @('BuiltInRole', 'CustomRole')) { throw 'Unknown role definition type.' }
    foreach ($perm in $permissions) {
        $actions = @(Get-CadmField $perm 'actions')
        if ($type -eq 'CustomRole') {
            foreach ($action in @($actions) + @(Get-CadmField $perm 'dataActions')) {
                if ($action -and $action -notmatch '^[a-zA-Z0-9.*_-]+(?:/[a-zA-Z0-9.*_-]+)*/read$') {
                    throw 'Custom standing roles must be read-only; use a reviewed eligibility for other permissions.'
                }
            }
        }
        foreach ($danger in @('Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleDefinitions/write',
            'Microsoft.Authorization/elevateAccess/action', 'Microsoft.Authorization/roleEligibilityScheduleRequests/write',
            'Microsoft.Authorization/roleAssignmentScheduleRequests/write')) {
            $allowed = @($actions | Where-Object { $_ -and $danger -like $_ }).Count -gt 0
            $excluded = @((Get-CadmField $perm 'notActions') | Where-Object { $_ -and $danger -like $_ }).Count -gt 0
            if ($allowed -and -not $excluded) { throw 'Standing role can administer access; use eligibility.' }
        }
    }
    return $id
}

function Resolve-GroupByName {
    # Profiles name groups (portable across a rename of the underlying id); resolve to id +
    # role-assignable flag once. Exact displayName match, must be unique.
    param([string]$Name)
    $r = Invoke-Rest -Url ("$GraphBase/groups?`$filter=displayName eq '$($Name -replace "'","''")'" +
                           "&`$select=id,displayName,isAssignableToRole,onPremisesSyncEnabled,groupTypes")
    $hits = @($r.value)
    if ($hits.Count -eq 0) { throw "group '$Name' not found." }
    if ($hits.Count -gt 1) { throw "group '$Name' is ambiguous ($($hits.Count) matches)." }
    return $hits[0]
}

function Resolve-ProfilePlan {
    # Turn a validated profile into the same row shape the clone path uses (Plane/Action/Item/
    # Scope/Detail), diffed against what the TARGET already holds so re-applies are idempotent
    # (SKIP-EXISTS). Returns the row list; grants nothing.
    param([object]$Profile, [object]$Target, [hashtable]$Tenant, [object[]]$Subs)
    $rows = [System.Collections.Generic.List[object]]::new()

    # --- RBAC (standing) ---
    # Queried per PROFILE SCOPE, not by sweeping subscriptions. A profile routinely names a
    # management-group scope (root-mg), and the sub sweep is both wasteful and easy to get wrong
    # for those. One exact query per row is cheap and unambiguous.
    #
    # Only DIRECT assignments count as already-present. A role conveyed by group membership is
    # deliberately NOT treated as satisfying the profile: the profile says "this account holds
    # Reader here", and letting a group path suppress the grant would silently revoke it the day
    # someone is removed from that group.
    foreach ($r in (Get-ProfileEntries $Profile.Data.Rbac)) {
        $scope = Resolve-CadmScope -Scope ([string]$r.Scope) -Tenant $Tenant
        $roleId = Resolve-CadmStandingRole -Role ([string]$r.Role) -Scope $scope
        $have = Invoke-AzJson -AzArgs @('role', 'assignment', 'list', '--assignee', $Target.id,
                                        '--scope', $scope, '-o', 'json')
        if ($script:LastAzError) { throw "Cannot read target RBAC: $script:LastAzError" }
        $direct = @($have | Where-Object {
            [string]$_.principalId -eq $Target.id -and
            (Get-RoleDefGuid $_.roleDefinitionId) -eq $roleId -and
            [string]$_.scope -eq $scope })
        if (@($direct | Where-Object { Test-CadmConditionalAssignment $_ }).Count) { throw 'Existing conditional RBAC must be reviewed; cannot replace it with standing unconditional access.' }
        $action = if ($direct.Count) { 'SKIP-EXISTS' } else { 'CREATE' }
        $rows.Add([pscustomobject]@{ Plane='RBAC'; Action=$action; Item=[string]$r.Role; Scope=$scope; Detail=$roleId })
    }

    # --- Plain group membership ---
    $tgtGroupIds = @{}
    if (@(Get-ProfileEntries $Profile.Data.GroupMemberships).Count) {
        foreach ($g in (Get-GroupsFor -PrincipalId $Target.id)) { $tgtGroupIds[$g.id] = $true }
    }
    foreach ($gm in (Get-ProfileEntries $Profile.Data.GroupMemberships)) {
        $g = Resolve-GroupByName -Name ([string]$gm.Group)
        if ($g.onPremisesSyncEnabled) { throw "profile group '$($gm.Group)' is on-prem synced - membership must be set in AD, not via a profile." }
        if ($g.isAssignableToRole) { throw "profile group '$($gm.Group)' is role-assignable - grant it as a PIM eligibility, not standing membership." }
        Assert-CadmStandingGroup -GroupId $g.id
        $action = if ($tgtGroupIds.ContainsKey($g.id)) { 'SKIP-EXISTS' } else { 'CREATE' }
        $rows.Add([pscustomobject]@{ Plane='GROUP'; Action=$action; Item=$g.displayName; Scope=$g.id; Detail='cloud-only' })
    }

    # --- PIM-for-Groups eligibilities ---
    # An UNREADABLE PIM plane must never resolve to CREATE. "I could not read it" is not "the
    # target does not have it": granting on that assumption re-grants an eligibility the target
    # already holds, and more importantly it means the plan is being written from a blind spot.
    # BLOCKED-PIM-UNKNOWN carries that distinction to the operator, exactly as the clone path
    # does - the first cut of this function silently emitted CREATE and was caught only because
    # a smoke run against an already-converted account showed two impossible rows.
    $needPim = (Get-ProfileEntries $Profile.Data.PimGroupEligibilities).Count -gt 0
    $tgtPimGrp = if ($needPim) { Get-PimGroupsFor -PrincipalId $Target.id } else { $null }
    $tgtEligKeys = @{}
    if ($needPim -and $tgtPimGrp.Ok) { foreach ($k in $tgtPimGrp.Map.Keys) { $tgtEligKeys[$k] = $true } }
    foreach ($e in (Get-ProfileEntries $Profile.Data.PimGroupEligibilities)) {
        $g = Resolve-GroupByName -Name ([string]$e.Group)
        $acc = if ($e.AccessId) { [string]$e.AccessId } else { 'member' }
        $key = "$($g.id)|$acc"
        $action = if (-not $tgtPimGrp.Ok) { 'BLOCKED-PIM-UNKNOWN' }
                  elseif ($tgtEligKeys.ContainsKey($key)) { 'SKIP-EXISTS' }
                  else { 'CREATE' }
        $detail = if (-not $tgtPimGrp.Ok) { "PIM plane unreadable: $($tgtPimGrp.Error)" } else { 'eligibility' }
        # Duration is optional. Omitted, the grant negotiates against the group's PIM policy at
        # apply time (see Resolve-PimGroupExpiration); set it to pin an explicit ISO-8601 term.
        $rows.Add([pscustomobject]@{ Plane='PIM-GRP'; Action=$action; Item="$($g.displayName) [$acc]"
                                     Scope=$g.id; Detail=$detail; AccessId=$acc; Duration=[string]$e.Duration })
    }

    # --- Directory-role (standard PIM) eligibilities ---
    # Separate plane from PIM for Groups: different API, different scope family, different
    # consent. An unreadable plane yields BLOCKED-PIM-UNKNOWN for the same reason it does on the
    # group plane - "could not read" is not "does not have".
    $needDir = (Get-ProfileEntries $Profile.Data.DirectoryRoleEligibilities).Count -gt 0
    $tgtDir = if ($needDir) { Get-DirRoleEligibilitiesFor -PrincipalId $Target.id } else { $null }
    foreach ($d in (Get-ProfileEntries $Profile.Data.DirectoryRoleEligibilities)) {
        $roleName = [string]$d.Role
        $dscope = if ($d.DirectoryScopeId) { [string]$d.DirectoryScopeId } else { '/' }
        $res = Resolve-DirectoryRoleId -Name $roleName
        # Unreadable role catalogue and unreadable eligibilities are the same class of problem:
        # the plan cannot be trusted, so say so rather than guessing in either direction.
        $blocked = (-not $res.Ok) -or (-not $tgtDir.Ok)
        $key = "$($res.Id)|$dscope".ToLower()
        $action = if ($blocked) { 'BLOCKED-PIM-UNKNOWN' }
                  elseif ($tgtDir.Map.ContainsKey($key)) { 'SKIP-EXISTS' }
                  else { 'CREATE' }
        $detail = if (-not $res.Ok) { "directory-role catalogue unreadable: $($res.Error)" }
                  elseif (-not $tgtDir.Ok) { "directory-role PIM plane unreadable: $($tgtDir.Error)" }
                  else { 'eligibility' }
        $rows.Add([pscustomobject]@{ Plane='PIM-DIR'; Action=$action; Item=$roleName; Scope=$dscope
                                     Detail=$detail; RoleDefinitionId=$res.Id; Duration=[string]$d.Duration })
    }

    return $rows
}

function Invoke-ProfileGrant {
    # Grant the CREATE rows of a resolved profile plan. Declarative and idempotent - every row
    # carries literal values, no source lookup. Returns @{ Ok; Fail }.
    param([object[]]$Rows, [object]$Target, [string]$Justification, [string]$TicketNumber,
          [string]$TicketSystem, [string]$DefaultDuration = 'P365D')
    $ok = 0; $fail = 0
    foreach ($item in @($Rows | Where-Object { $_.Action -eq 'CREATE' })) {
        switch ($item.Plane) {
            'RBAC' {
                $canonicalScope = Resolve-CadmScope -Scope $item.Scope -Tenant @{}
                $roleId = Resolve-CadmStandingRole -Role $item.Detail -Scope $canonicalScope
                $null = Invoke-AzJson -AzArgs @('role', 'assignment', 'create',
                    '--assignee-object-id', $Target.id, '--assignee-principal-type', 'User',
                    '--role', $roleId, '--scope', $canonicalScope, '-o', 'json')
                if ($script:LastAzError) { Write-Host "  [FAIL] RBAC    $($item.Item) @ $($item.Scope): $script:LastAzError"; $fail++ }
                else { Write-Host "  [OK]   RBAC    $($item.Item) @ $($item.Scope)"; $ok++ }
            }
            'GROUP' {
                Add-CadmStandingGroupMember -GroupId $item.Scope -PrincipalId $Target.id
                if ($script:LastAzError) { Write-Host "  [FAIL] GROUP   $($item.Item): $script:LastAzError"; $fail++ }
                else { Write-Host "  [OK]   GROUP   $($item.Item)"; $ok++ }
            }
            'PIM-GRP' {
                # Eligibility, never standing access. The expiration is negotiated against the
                # group's own PIM policy rather than hardcoded: a policy that forbids permanent
                # eligibility rejects noExpiration outright with
                #   ExpirationRule - The policy does not allow permanent assignment
                # which is a policy conflict rather than an authentication failure.
                $expiration = Resolve-PimGroupExpiration -GroupId $item.Scope -AccessId $item.AccessId `
                                                         -Duration $item.Duration -DefaultDuration $DefaultDuration
                $body = @{
                    accessId      = $item.AccessId
                    principalId   = $Target.id
                    groupId       = $item.Scope
                    action        = 'adminAssign'
                    justification = $Justification
                    scheduleInfo  = @{ startDateTime = (Get-Date).ToUniversalTime().ToString('o'); expiration = $expiration }
                }
                if ($TicketNumber -or $TicketSystem) { $body.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
                $r = Invoke-MgJson -Method POST -Body $body `
                        -Uri "$GraphBase/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests"
                if ($r.Ok) { Write-Host "  [OK]   PIM-GRP $($item.Item)"; $ok++ }
                else { Write-Host "  [FAIL] PIM-GRP $($item.Item): $($r.Error)"; $fail++ }
            }
            'PIM-DIR' {
                # Standard PIM: an ELIGIBILITY for a directory role, tenant-scoped. adminAssign
                # against roleEligibilityScheduleRequests - NEVER roleAssignmentScheduleRequests,
                # which would make the role active and standing.
                #
                # Activation gates (MFA, justification, approval, max duration) belong to the
                # role's own PIM policy and are not set here: they apply to everyone eligible for
                # the role, so they are a tenant decision rather than a per-user one.
                $dur = Select-CadmDuration -MaxDuration (Get-DirRoleExpirationRule -RoleDefinitionId $item.RoleDefinitionId).MaxDuration `
                                           -DefaultDuration $(if ($item.Duration) { $item.Duration } else { $DefaultDuration })
                $body = @{
                    action           = 'adminAssign'
                    roleDefinitionId = $item.RoleDefinitionId
                    principalId      = $Target.id
                    directoryScopeId = $item.Scope
                    justification    = $Justification
                    scheduleInfo     = @{
                        startDateTime = (Get-Date).ToUniversalTime().ToString('o')
                        expiration    = @{ type = 'afterDuration'; duration = $dur }
                    }
                }
                if ($TicketNumber -or $TicketSystem) { $body.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
                $r = Invoke-MgJson -Method POST -Body $body `
                        -Uri "$GraphBase/roleManagement/directory/roleEligibilityScheduleRequests"
                if ($r.Ok) { Write-Host "  [OK]   PIM-DIR $($item.Item) (eligible, $dur)"; $ok++ }
                else { Write-Host "  [FAIL] PIM-DIR $($item.Item): $($r.Error)"; $fail++ }
            }
        }
    }
    return @{ Ok = $ok; Fail = $fail }
}
