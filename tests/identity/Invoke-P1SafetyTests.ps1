#requires -Version 5.1
# Offline behavioral regressions. Every cloud transport is mocked; no credentials needed.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$core = Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1'
$profileLib = Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1'
$script:passed = 0
function Assert-True { param($Value, [string]$Message) if (-not $Value) { throw $Message } }
function Assert-Throws { param([scriptblock]$Action) $thrown = $false; try { & $Action | Out-Null } catch { $thrown = $true }; Assert-True $thrown 'Expected refusal.' }
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    & {
        . $core
        . $profileLib
        $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
        $script:actualTenant = $script:ExpectedTenantId
        $script:cloud = 'AzureCloud'; $script:graphCloud = 'Global'; $script:writes = 0
        $script:scopeTenant = $script:ExpectedTenantId
        $script:scope = '/subscriptions/22222222-2222-2222-2222-222222222222'
        $script:roleId = '33333333-3333-3333-3333-333333333333'
        $script:groupMode = 'plain'; $script:rbacError = ''
        $script:role = @{ id = "/providers/Microsoft.Authorization/roleDefinitions/$script:roleId"; roleName = 'Reader'; roleType = 'BuiltInRole'; permissions = @(@{ actions = @('*/read'); notActions = @(); dataActions = @() }) }
        $script:have = @()
        function Write-Host { }
        function Invoke-AzJsonRaw {
            param([string[]]$AzArgs)
            $script:LastAzError = ''
            if ($AzArgs[0] -eq 'account' -and $AzArgs[1] -eq 'show') {
                $tid = if ($AzArgs -contains '--subscription') { $script:scopeTenant } else { $script:actualTenant }
                return @{ tenantId = $tid; environmentName = $script:cloud }
            }
            if ($AzArgs[0] -eq 'role' -and $AzArgs[1] -eq 'definition') { return $script:role }
            if ($AzArgs[0] -eq 'role' -and $AzArgs[2] -eq 'list') { $script:LastAzError = $script:rbacError; return $script:have }
            if ($AzArgs -contains 'create' -or $AzArgs -contains 'add') { $script:writes++; return @{ id = 'created' } }
            if ($AzArgs[0] -eq 'rest') {
                $uri = $AzArgs[[array]::IndexOf($AzArgs, '--url') + 1]
                if ($uri -match '/groups/[^/?]+\?') {
                    return @{ id = 'group'; isAssignableToRole = ($script:groupMode -eq 'role'); onPremisesSyncEnabled = $false; groupTypes = @() }
                }
                if ($uri -match 'managementGroups') { return @{ properties = @{ tenantId = $script:scopeTenant } } }
                return @{ value = @() }
            }
            throw 'Unexpected Azure call in test.'
        }
        function Get-MgContext { [pscustomobject]@{ TenantId = $script:actualTenant; Environment = $script:graphCloud; Scopes = @('Group.Read.All') } }
        function Invoke-MgGraphRequest {
            param($Method, $Uri, $Body, $ErrorAction)
            if ($Method -ne 'GET') { $script:writes++; return @{} }
            if ($script:groupMode -eq 'unknown') { throw '403 Forbidden' }
            if ($script:groupMode -eq 'pim') { return @{ value = @(@{ id = 'pim-policy' }) } }
            return @{ value = @() }
        }
        $target = @{ id = 'target'; accountEnabled = $true }
        $tenant = @{ ScopeTokens = @{ safe = $script:scope } }
        $prof = @{ Name = 'Synthetic'; Data = @{ Rbac = @(@{ Role = 'Reader'; Scope = 'safe' }) } }
        & $Action
    }
    $script:passed++
    Write-Host "PASS $Name"
}

Test-Case 'Plain cloud group remains writable' {
    Add-CadmStandingGroupMember -GroupId group -PrincipalId target
    Assert-True ($script:writes -eq 1) 'Expected one legitimate membership write.'
}
foreach ($mode in @('pim', 'unknown', 'role')) {
    Test-Case "Standing group $mode rejected at sink" {
        $script:groupMode = $mode
        Assert-Throws { Add-CadmStandingGroupMember -GroupId group -PrincipalId target }
        Assert-True ($script:writes -eq 0) 'Unsafe group write occurred.'
    }
}
Test-Case 'PIM group rejected during profile planning' {
    $script:groupMode = 'pim'
    function Resolve-GroupByName { @{ id = 'group'; displayName = 'Example'; isAssignableToRole = $false; onPremisesSyncEnabled = $false } }
    $prof.Data = @{ GroupMemberships = @(@{ Group = 'Example' }) }
    Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
    Assert-True ($script:writes -eq 0) 'Planning wrote access.'
}
Test-Case 'Changed group governance blocks stale profile plan' {
    $row = @{ Plane = 'GROUP'; Action = 'CREATE'; Item = 'Example'; Scope = 'group' }
    $script:groupMode = 'unknown'
    Assert-Throws { Invoke-ProfileGrant -Rows @($row) -Target $target }
    Assert-True ($script:writes -eq 0) 'Stale plan wrote access.'
}
Test-Case 'Successful empty profile RBAC read permits CREATE' {
    $rows = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
    Assert-True ($rows.Count -eq 1 -and $rows[0].Action -eq 'CREATE') 'Empty success was not distinguished from failure.'
    $result = Invoke-ProfileGrant -Rows $rows -Target $target
    Assert-True ($result.Ok -eq 1 -and $script:writes -eq 1) 'Legitimate Reader failed.'
}
foreach ($errorText in @('403 Forbidden', '429 TooManyRequests', 'network error', 'unparseable JSON')) {
    Test-Case "Failed profile RBAC read: $errorText" {
        $script:rbacError = $errorText
        Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
        Assert-True ($script:writes -eq 0) 'Failed discovery wrote access.'
    }
    Test-Case "Failed activation discovery: $errorText" {
        function Invoke-Rest { $script:LastAzError = $errorText; return $null }
        $r = Get-PimActivatedFor -PrincipalId source -Subs @(@{ Id = 'sub' })
        Assert-True $r.Denied 'Failed activation read looked complete.'
    }
}
Test-Case 'Successful empty activation discovery' {
    $r = Get-PimActivatedFor -PrincipalId source -Subs @(@{ Id = 'sub' })
    Assert-True (-not $r.Denied -and $r.Map.Count -eq 0) 'Empty activation data blocked.'
}
Test-Case 'Second ARM page failure marks activation unknown' {
    function Invoke-Rest { param($Url)
        if ($Url -eq 'next') { throw 'network failure' }
        return @{ value = @(); nextLink = 'next' }
    }
    $r = Get-PimActivatedFor -PrincipalId source -Subs @(@{ Id = 'sub' })
    Assert-True $r.Denied 'Partial ARM data looked complete.'
}
Test-Case 'Expiring Assigned and Activated schedules excluded from standing' {
    function Invoke-Rest { return @{ value = @(@{ properties = @{ assignmentType = 'Assigned'; endDateTime = '2099-01-01'; roleDefinitionId = $script:roleId; expandedProperties = @{ scope = @{ id = $script:scope }; roleDefinition = @{ displayName = 'Reader' } } } }) } }
    $r = Get-PimActivatedFor -PrincipalId source -Subs @(@{ Id = 'sub' })
    Assert-True ($r.Map.Count -eq 1) 'Expiring Assigned schedule was treated as permanent.'
}
Test-Case 'Failed group active read invalidates eligibility success' {
    function Invoke-MgJsonAll { param($Uri)
        if ($Uri -match '/assignmentScheduleInstances') { return @{ Ok = $false; Error = '429'; Value = @() } }
        return @{ Ok = $true; Value = @() }
    }
    $r = Get-PimGroupsFor -PrincipalId source
    Assert-True (-not $r.Ok) 'Failed active read looked complete.'
}
Test-Case 'Graph page limit is incomplete' {
    function Invoke-MgJson { return @{ Ok = $true; Value = @(); Next = 'next' } }
    $r = Invoke-MgJsonAll -Uri first
    Assert-True (-not $r.Ok) 'Page cap looked complete.'
}
Test-Case 'Malformed Graph collection is incomplete' {
    function Invoke-MgGraphRequest { return @{} }
    $r = Invoke-MgJsonAll -Uri "$GraphBase/groups?`$top=999"
    Assert-True (-not $r.Ok) 'Malformed response looked empty.'
}
Test-Case 'Owner GUID and full ID blocked' {
    foreach ($role in @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635')) {
        $prof.Data.Rbac[0].Role = $role
        Assert-Throws { Assert-ProfileSafe -Profile $prof -Tenant $tenant }
    }
}
Test-Case 'Resolved privileged role blocked at grant' {
    $script:role.id = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    Assert-Throws { Invoke-ProfileGrant -Rows @(@{ Plane = 'RBAC'; Action = 'CREATE'; Detail = 'renamed'; Scope = $script:scope }) -Target $target }
    Assert-True ($script:writes -eq 0) 'Privileged role reached sink.'
}
foreach ($badScope in @('/', ' /', '/subscriptions/22222222-2222-2222-2222-222222222222/../', '/subscriptions/22222222-2222-2222-2222-222222222222%2f', '/subscriptions/22222222-2222-2222-2222-222222222222?x=1', '/providers/Microsoft.Management/managementGroups/example/')) {
    Test-Case "Unsafe scope alias: $badScope" {
        $tenant.ScopeTokens.safe = $badScope
        Assert-Throws { Resolve-CadmScope -Scope safe -Tenant $tenant }
    }
}
Test-Case 'Custom wildcard role blocked; custom reader retained' {
    $script:role.roleType = 'CustomRole'
    $script:role.permissions[0].actions = @('*')
    Assert-Throws { Resolve-CadmStandingRole -Role custom -Scope $script:scope }
    $script:role.permissions[0].actions = @('Microsoft.Compute/*/read')
    Assert-True ((Resolve-CadmStandingRole -Role custom -Scope $script:scope) -eq $script:roleId) 'Read-only custom role rejected.'
}
Test-Case 'Permission blocks cannot cancel each others authorization grants' {
    $script:role.permissions = @(@{ actions = @('*'); notActions = @('Microsoft.Authorization/*') }, @{ actions = @('Microsoft.Authorization/roleAssignments/write'); notActions = @() })
    Assert-Throws { Resolve-CadmStandingRole -Role custom -Scope $script:scope }
}
Test-Case 'Condition and conditionVersion both block lossy copying' {
    Assert-True (Test-CadmConditionalAssignment @{ condition = 'restricted' }) 'Condition lost.'
    Assert-True (Test-CadmConditionalAssignment @{ conditionVersion = '2.0' }) 'Condition version lost.'
    Assert-True (-not (Test-CadmConditionalAssignment @{})) 'Plain assignment blocked.'
}
Test-Case 'Profile does not overwrite target conditional assignment' {
    $script:have = @(@{ principalId = 'target'; roleDefinitionId = $script:roleId; scope = $script:scope; condition = 'restricted' })
    Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
}
Test-Case 'Resource eligibility retains condition metadata for rejection' {
    function Invoke-Rest { return @{ value = @(@{ properties = @{ roleDefinitionId = $script:roleId; endDateTime = $null; condition = 'restricted'; conditionVersion = '2.0'; expandedProperties = @{ scope = @{ id = $script:scope }; roleDefinition = @{ displayName = 'Reader' } } } }) } }
    $r = Get-PimResourceFor -PrincipalId source -Subs @(@{ Id = 'sub' })
    Assert-True (Test-CadmConditionalAssignment @($r.Map.Values)[0]) 'Resource PIM condition dropped.'
}
Test-Case 'Wrong Azure tenant fails before transport write' {
    $script:actualTenant = '44444444-4444-4444-4444-444444444444'
    Assert-Throws { Invoke-AzJson -AzArgs @('ad', 'group', 'member', 'add') }
    Assert-True ($script:writes -eq 0) 'Wrong tenant wrote.'
}
Test-Case 'Wrong Graph tenant fails before transport write' {
    $script:actualTenant = '44444444-4444-4444-4444-444444444444'
    Assert-True (-not (Test-MgConnected)) 'Wrong Graph tenant accepted.'
    $r = Invoke-MgJson -Uri "$GraphBase/groups" -Method POST -Body @{ value = 'test' }
    Assert-True (-not $r.Ok -and $script:writes -eq 0) 'Wrong Graph tenant wrote.'
}
Test-Case 'Cloud mismatch and untrusted paging hosts rejected' {
    $script:cloud = 'AzureUSGovernment'
    Assert-Throws { Assert-CadmAzContext }
    $script:graphCloud = 'USGov'
    Assert-True (-not (Test-MgConnected)) 'Wrong Graph cloud accepted.'
    Assert-Throws { Assert-CadmApiUri -Uri 'https://example.com/page2' -Hosts @('graph.microsoft.com') }
}
Test-Case 'Foreign subscription and management-group scope rejected' {
    $script:scopeTenant = '44444444-4444-4444-4444-444444444444'
    Assert-Throws { Assert-CadmScopeTenant -Scope $script:scope }
    Assert-Throws { Assert-CadmScopeTenant -Scope '/providers/Microsoft.Management/managementGroups/example' }
    Assert-True ($script:writes -eq 0) 'Foreign scope wrote.'
}
Test-Case 'Zero tenant binding rejected' { Assert-Throws { Set-CadmTenant -TenantId '00000000-0000-0000-0000-000000000000' } }
Test-Case 'CLI list JSON distinguishes empty arrays from malformed or missing data' {
    . $core
    $script:AzExe = 'Invoke-FakeAz'
    function Invoke-FakeAz { $global:LASTEXITCODE = 0; return $script:rawText }
    foreach ($bad in @('{}', 'null', '', 'not-json')) {
        $script:rawText = $bad
        $null = Invoke-AzJsonRaw -AzArgs @('role', 'assignment', 'list')
        Assert-True ([bool]$script:LastAzError) 'Malformed list looked empty.'
    }
    $script:rawText = '[]'
    $null = Invoke-AzJsonRaw -AzArgs @('role', 'assignment', 'list')
    Assert-True (-not $script:LastAzError) 'Valid empty list rejected.'
    $script:rawText = ''
    $null = Invoke-AzJsonRaw -AzArgs @('ad', 'group', 'member', 'add')
    Assert-True (-not $script:LastAzError) 'Successful empty membership response rejected.'
}
Test-Case 'Subscription inventory preserves only bound tenant and cloud' {
    function Invoke-AzJson { return @(
        @{ id = 'one'; name = 'One'; tenantId = $script:ExpectedTenantId; environmentName = 'AzureCloud' },
        @{ id = 'two'; name = 'Two'; tenantId = '44444444-4444-4444-4444-444444444444'; environmentName = 'AzureCloud' },
        @{ id = 'three'; name = 'Three'; tenantId = $script:ExpectedTenantId; environmentName = 'AzureUSGovernment' }) }
    $subs = @(Get-Subscriptions)
    Assert-True ($subs.Count -eq 1 -and $subs[0].Id -eq 'one' -and $subs[0].TenantId -eq $script:ExpectedTenantId) 'Foreign inventory retained.'
}
Test-Case 'Partial per-group active read is never complete' {
    function Get-PimCandidateGroupIds { @('first', 'second') }
    function Invoke-MgJsonAll { param($Uri)
        if ($Uri -match 'principalId' -or ($Uri -match 'assignmentScheduleInstances' -and $Uri -match 'second')) { return @{ Ok = $false; Error = '403'; Value = @() } }
        return @{ Ok = $true; Value = @() }
    }
    Assert-True (-not (Get-PimGroupsFor -PrincipalId source).Ok) 'Partial active fallback accepted.'
}
Test-Case 'Existing unconditional Reader remains idempotent' {
    $script:have = @(@{ principalId = 'target'; roleDefinitionId = $script:roleId; scope = $script:scope })
    $rows = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
    Assert-True ($rows.Count -eq 1 -and $rows[0].Action -eq 'SKIP-EXISTS') 'Existing Reader was not recognized.'
}

# Execute the complete clone entry point with only its transport/bootstrap replaced.
# Keep its real StrictMode, planning, preflight, apply loop, and tenant enforcement.
foreach ($scenario in @('normal', 'condition', 'target-condition', 'eligibility-condition', 'activation-error', 'expiring-assigned', 'tenant-switch')) {
    Test-Case "Clone entry point: $scenario" {
        $script:cloneScenario = $scenario; $script:capturedAudit = ''; $script:transportWrites = 0
        $mockSetup = {
            $script:AzExe = 'offline-test'
            function Initialize-AzInvoker { }
            function Write-Host { }
            function New-Item { }
            function Set-Content { param($Path, [Parameter(ValueFromPipeline=$true)]$Value, $Encoding) process { $script:capturedAudit = $Value } }
            function Invoke-AzJsonRaw {
                param([string[]]$AzArgs)
                $script:LastAzError = ''
                if ($AzArgs[0] -eq 'account') {
                    $tid = if ($script:cloneScenario -eq 'tenant-switch' -and $script:capturedAudit) { '44444444-4444-4444-4444-444444444444' } else { '11111111-1111-1111-1111-111111111111' }
                    return [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; name = 'Example'; tenantId = $tid; environmentName = 'AzureCloud'; user = @{ name = 'synthetic@example.com' } }
                }
                if ($AzArgs -contains 'create') { $script:transportWrites++; return @{ id = 'new-assignment' } }
                if ($AzArgs[0] -eq 'role') {
                    $who = $AzArgs[[array]::IndexOf($AzArgs, '--assignee') + 1]
                    if ($who -eq 'target' -and $script:cloneScenario -ne 'target-condition') { return @() }
                    return [pscustomobject]@{ principalId = $who; principalType = 'User'; roleDefinitionId = '33333333-3333-3333-3333-333333333333'; roleDefinitionName = 'Reader'; scope = '/subscriptions/22222222-2222-2222-2222-222222222222'; condition = $(if ($script:cloneScenario -eq 'condition' -or ($who -eq 'target' -and $script:cloneScenario -eq 'target-condition')) { 'restricted' } else { $null }); conditionVersion = $null }
                }
                if ($AzArgs[0] -eq 'rest') {
                    $uri = $AzArgs[[array]::IndexOf($AzArgs, '--url') + 1]
                    if ($uri -match '/users/(source|target)(?:@|%40)example.com') {
                        $who = $Matches[1]
                        return [pscustomobject]@{ id = $who; displayName = 'Synthetic'; userPrincipalName = "$who@example.com"; accountEnabled = $true; onPremisesSyncEnabled = $false }
                    }
                    if ($uri -match 'roleAssignmentScheduleInstances' -and $script:cloneScenario -eq 'activation-error') { $script:LastAzError = '429 TooManyRequests'; return $null }
                    if (($uri -match 'roleAssignmentScheduleInstances' -and $script:cloneScenario -eq 'expiring-assigned') -or
                        ($uri -match 'roleEligibilityScheduleInstances' -and $uri -match "source" -and $script:cloneScenario -eq 'eligibility-condition')) {
                        return @{ value = @(@{ properties = @{ assignmentType = 'Assigned'; endDateTime = '2099-01-01'; condition = 'restricted'; conditionVersion = '2.0'; roleDefinitionId = '33333333-3333-3333-3333-333333333333'; expandedProperties = @{ scope = @{ id = '/subscriptions/22222222-2222-2222-2222-222222222222' }; roleDefinition = @{ displayName = 'Reader' } } } }) }
                    }
                    return @{ value = @() }
                }
                throw 'Unexpected clone transport call.'
            }
        }
        $source = Get-Content (Join-Path $root 'scripts/Copy-CadmAccess.ps1') -Raw
        $source = $source.Replace(". (Join-Path `$PSScriptRoot 'cadm\lib\CadmAccess.Core.ps1')", '. $core; . $mockSetup')
        $entry = [scriptblock]::Create($source)
        $argsForClone = @{ TenantId = '11111111-1111-1111-1111-111111111111'; SourceUser = 'source@example.com'; TargetUser = 'target@example.com'; SkipGroups = $true; Apply = $true; Force = $true; OutDir = $root }
        if ($scenario -in @('activation-error', 'tenant-switch')) { Assert-Throws { & $entry @argsForClone } }
        else { & $entry @argsForClone }
        $audit = $script:capturedAudit | ConvertFrom-Json
        Assert-True ($null -ne $audit) 'Clone did not reach auditable planning.'
        $expectedWrites = if ($scenario -in @('normal', 'eligibility-condition')) { 1 } else { 0 }
        Assert-True ($script:transportWrites -eq $expectedWrites) "Unexpected clone writes: $script:transportWrites."
        if ($scenario -match 'condition') {
            Assert-True (@($audit.plan | Where-Object { $_.Action -eq 'BLOCKED-CONDITIONAL' }).Count -gt 0) 'Conditional plan was not blocked.'
        }
    }
}
Write-Host "$script:passed P1 safety checks passed. Offline mocks only; no live tenant writes."
