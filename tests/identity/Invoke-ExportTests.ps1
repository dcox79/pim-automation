#requires -Version 5.1
# Offline export -> PSD1 -> preview/grant regressions. Every cloud transport is mocked.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$core = Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1'
$profileLib = Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1'
$exportLib = Join-Path $root 'scripts/cadm/lib/CadmExport.ps1'
$testBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $testBase ("cadm-export-tests-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $testRoot | Out-Null
$script:passed = 0
function Assert-True { param($Value, [string]$Message) if (-not $Value) { throw $Message } }
function Assert-Throws { param([scriptblock]$Action) $thrown=$false; try { & $Action | Out-Null } catch { $thrown=$true }; Assert-True $thrown 'Expected refusal.' }
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    & {
        $Apply=$false; $Interactive=$false
        . $core
        . $profileLib
        . $exportLib
        $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
        $script:actualTenant = $script:ExpectedTenantId
        $script:sourceId = '22222222-2222-2222-2222-222222222222'
        $script:targetId = '33333333-3333-3333-3333-333333333333'
        $script:roleId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $script:groupId = '44444444-4444-4444-4444-444444444444'
        $script:directoryId = '55555555-5555-5555-5555-555555555555'
        $script:scope = '/providers/Microsoft.Management/managementGroups/11111111-1111-1111-1111-111111111111'
        $script:end = [datetimeoffset]::UtcNow.AddDays(10).ToString('o')
        $script:start = [datetimeoffset]::UtcNow.AddDays(-1).ToString('o')
        $script:mode = 'normal'; $script:maximum = 'P365D'; $script:writes = @(); $script:targetRows = @()
        $script:sourceRows = @(@{ properties = @{
            principalId = $script:sourceId; scope = $script:scope; roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$script:roleId"
            startDateTime = $script:start; endDateTime = $script:end
            expandedProperties = @{ roleDefinition = @{ displayName = 'Owner' } }; condition = $null; conditionVersion = $null
        } })
        $source = @{ id = $script:sourceId; userPrincipalName = 'source@example.com'; displayName = 'Synthetic source' }
        $target = @{ id = $script:targetId; accountEnabled = $true }
        $tenant = @{ TenantId = $script:ExpectedTenantId; ProfilesDir = (Join-Path $testRoot ([guid]::NewGuid().ToString())); DefaultEligibilityDuration = 'P30D'; ScopeTokens = @{} }
        New-Item -ItemType Directory -Path $tenant.ProfilesDir | Out-Null
        $tenant.Path=Join-Path $testRoot ('tenant-'+[guid]::NewGuid()+'.psd1')
        [IO.File]::WriteAllText($tenant.Path,'@{}')
        function Write-Host { }
        function Invoke-AzJsonRaw {
            param([string[]]$AzArgs)
            $script:LastAzError = ''
            if ($AzArgs[0] -eq 'account' -and $AzArgs[1] -eq 'show') { return @{ tenantId = $script:actualTenant; environmentName = 'AzureCloud'; user = @{ name = 'operator@example.com' } } }
            if ($AzArgs[0] -eq 'account' -and $AzArgs[1] -eq 'list') {
                return @('66666666-6666-6666-6666-666666666666', '77777777-7777-7777-7777-777777777777') | ForEach-Object { @{ id = $_; name = 'Synthetic subscription'; tenantId = $script:actualTenant; cloudName = 'AzureCloud' } }
            }
            if ($AzArgs[0] -eq 'role' -and $AzArgs[1] -eq 'definition') { return @{ id = "/providers/Microsoft.Authorization/roleDefinitions/$script:roleId"; roleName = 'Owner' } }
            throw 'Unexpected Azure CLI operation.'
        }
        function Invoke-Rest {
            param([string]$Url, [string]$Method = 'get', [string]$BodyFile)
            $script:LastAzError = ''
            if ($Method -ne 'get') {
                Assert-True ($Method -eq 'put' -and $Url -match '/roleEligibilityScheduleRequests/') 'Unexpected cloud write.'
                $script:writes += @{ Url = $Url; Body = (Get-Content -LiteralPath $BodyFile -Raw | ConvertFrom-Json) }
                return @{ id = 'request-id' }
            }
            if ($Url -match 'next-page') { throw '429 partial page' }
            if ($Url -match 'roleManagementPolicyAssignments') {
                if ($script:mode -eq 'unreadable-policy') { throw '403 policy' }
                return @{ value = @(@{ properties = @{ roleDefinitionId = $script:roleId; effectiveRules = @(
                    @{ id = 'Expiration_Admin_Eligibility'; maximumDuration = $script:maximum },
                    @{ id='Enablement_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};enabledRules=@('MultiFactorAuthentication') },
                    @{ id='Approval_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};setting=@{isApprovalRequired=$true;approvalStages=@(@{primaryApprovers=@(@{id='88888888-8888-8888-8888-888888888888';userType='Group'})})} },
                    @{ id='Expiration_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};isExpirationRequired=$true;maximumDuration='PT2H' }
                ) } }) }
            }
            if ($Url -match '/roleEligibilityScheduleInstances') {
                $decoded = [uri]::UnescapeDataString($Url)
                if ($decoded -match $script:targetId) { return @{ value = @($script:targetRows) } }
                Assert-True ($decoded -match $script:sourceId) 'Wrong principal query.'
                if ($script:mode -eq 'partial-page') { return @{ value = $script:sourceRows; nextLink = 'https://management.azure.com/next-page' } }
                if ($script:mode -eq 'conflicting-schedules' -and $Url -match '77777777') { $script:sourceRows[0].properties.endDateTime = [datetimeoffset]::UtcNow.AddDays(5).ToString('o') }
                return @{ value = @($script:sourceRows) }
            }
            if ($Url -match '/managementGroups/[^/?]+\?') { return @{ properties = @{ tenantId = $script:actualTenant } } }
            throw "Unexpected ARM read: $Url"
        }
        function Get-MgContext { return @{ TenantId = $script:actualTenant; Environment = 'Global' } }
        function Invoke-MgGraphRequest {
            param($Method, $Uri, $Body, $ErrorAction)
            if ($Method -ne 'GET') {
                Assert-True ($Method -eq 'POST' -and $Uri -match 'eligibilityScheduleRequests|roleEligibilityScheduleRequests') 'Unexpected Graph write.'
                $script:writes += @{ Url = $Uri; Body = ($Body | ConvertFrom-Json) }
                return @{ id = 'graph-request' }
            }
            if ($script:mode -eq 'graph-denied') { throw '403 Graph denied' }
            if ($Uri -match '/policies/') { return @{ value = @(@{ policy = @{ rules = @(@{ id = 'Expiration_Admin_Eligibility'; maximumDuration = $script:maximum }) } }) } }
            if ($Uri -match '/groups/') { return @{ id = $script:groupId; displayName = 'Synthetic group' } }
            if ($Uri -match '/roleDefinitions/') { return @{ id = $script:directoryId; displayName = 'Security Reader' } }
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match $script:targetId -or $Uri -match '/assignmentScheduleInstances') { return @{ value = @() } }
            if ($Uri -match '/privilegedAccess/group/eligibilityScheduleInstances') {
                return @{ value = @('member', 'owner') | ForEach-Object { @{
                    principalId = $script:sourceId; groupId = $script:groupId; accessId = $_; startDateTime = $script:start
                    endDateTime = $(if ($_ -eq 'owner') { [datetimeoffset]::UtcNow.AddDays(5).ToString('o') } else { $script:end })
                } } }
            }
            if ($Uri -match '/directory/roleEligibilityScheduleInstances') {
                return @{ value = @(@{ principalId = $script:sourceId; roleDefinitionId = $script:directoryId; directoryScopeId = '/'; appScopeId = $null; startDateTime = $script:start; endDateTime = $script:end }) }
            }
            throw "Unexpected Graph read: $Uri"
        }
        function Export-TestProfile { param([string]$Key = 'test', [string[]]$Planes = @('AzureResource'), [string]$Duration)
            Export-CadmEligibilityProfile -Source $source -Tenant $tenant -ProfileName $Key -Planes $Planes -Duration $Duration
        }
        & $Action
    }
    $script:passed++
    Write-Host "PASS $Name"
}
try {
    Test-Case 'Azure export round-trips Owner as eligibility and deduplicates inherited results' {
        $result = Export-TestProfile
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.PimResourceEligibilities.Count -eq 1 -and $data.Rbac.Count -eq 0 -and $data.GroupMemberships.Count -eq 0) 'Standing or duplicate access exported.'
        Assert-True ($data.PimResourceEligibilities[0].EndDateTime -eq $script:end) 'Expiry was changed.'
        Assert-True ($data.Export.Planes.Count -eq 1 -and $data.Export.SubscriptionIds.Count -eq 2) 'Discovery coverage missing.'
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $plan = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        Assert-True ($plan.Count -eq 1 -and $plan[0].Plane -eq 'PIM-RES' -and $plan[0].Action -eq 'CREATE') ("Export cannot be previewed: " + ($plan | ConvertTo-Json -Depth 15 -Compress))
        Assert-True ($script:writes.Count -eq 0) 'Export or preview wrote cloud access.'
    }
    Test-Case 'Profile eligibility apply uses AdminAssign eligibility and preserves expiry' {
        $result = Export-TestProfile
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $plan = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        $granted = Invoke-ProfileGrant -Rows $plan -Target $target -Justification 'Test'
        Assert-True ($granted.Ok -eq 1 -and $script:writes.Count -eq 1) 'Eligibility request missing.'
        $body = $script:writes[0].Body.properties
        Assert-True ($body.requestType -eq 'AdminAssign' -and $body.principalId -eq $target.id -and $body.scheduleInfo.expiration.endDateTime -eq $script:end) 'Wrong grant or expiry.'
    }
    Test-Case 'Existing eligibility is retained without a write or renewal' {
        $null = Export-TestProfile
        $script:targetRows = @(@{ properties = @{ principalId = $target.id; scope = $script:scope; roleDefinitionId = $script:roleId } })
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $plan = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        Assert-True ($plan[0].Action -eq 'SKIP-EXISTS') 'Existing eligibility missed.'
        $null = Invoke-ProfileGrant -Rows $plan -Target $target
        Assert-True ($script:writes.Count -eq 0) 'Existing eligibility rewritten.'
    }
    foreach ($bad in @('conditional', 'partial-page', 'conflicting-schedules', 'missing-expiry', 'expired', 'foreign-principal')) {
        Test-Case "Export refuses $bad without saving a profile" {
            $script:mode = $bad
            switch ($bad) {
                'conditional' { $script:sourceRows[0].properties.condition = 'restricted' }
                'missing-expiry' { $script:sourceRows[0].properties.Remove('endDateTime') }
                'expired' { $script:sourceRows[0].properties.endDateTime = '2000-01-01T00:00:00Z' }
                'foreign-principal' { $script:sourceRows[0].properties.principalId = $target.id }
            }
            Assert-Throws { Export-TestProfile }
            Assert-True (@(Get-ChildItem -LiteralPath $tenant.ProfilesDir -Force).Count -eq 0) 'Partial profile saved.'
            Assert-True ($script:writes.Count -eq 0) 'Export wrote cloud access.'
        }
    }
    Test-Case 'An export never overwrites an existing profile' {
        $result = Export-TestProfile
        $before = [IO.File]::ReadAllText($result.Path)
        Assert-Throws { Export-TestProfile }
        Assert-True ([IO.File]::ReadAllText($result.Path) -ceq $before) 'Existing profile changed.'
    }
    Test-Case 'Unsafe profile paths and reserved filenames are refused' {
        foreach ($key in @('../escape', 'sub/profile', 'con', 'nul', 'name.psd1', '')) { Assert-Throws { Export-TestProfile -Key $key } }
    }
    Test-Case 'Data serializer quotes text without executing it' {
        $source.userPrincipalName = "O'Brien" + '$(' + "throw 'executed')" + '@example.com'
        $result = Export-TestProfile
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.Export.SourceUserPrincipalName -ceq $source.userPrincipalName) 'Text did not round-trip safely.'
    }
    Test-Case 'Permanent eligibility becomes bounded and an explicit fresh duration is honored' {
        $script:sourceRows[0].properties.endDateTime = $null
        $result = Export-TestProfile -Key bounded
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.PimResourceEligibilities[0].Duration -eq 'P30D') 'Permanent eligibility copied.'
        $result = Export-TestProfile -Key fresh -Duration P14D
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.PimResourceEligibilities[0].Duration -eq 'P14D' -and -not $data.PimResourceEligibilities[0].ContainsKey('EndDateTime')) 'Fresh duration ignored.'
    }
    Test-Case 'Empty discovery does not create a misleading empty profile' {
        $script:sourceRows = @()
        Assert-Throws { Export-TestProfile }
        Assert-True (@(Get-ChildItem $tenant.ProfilesDir -Force).Count -eq 0) 'Empty profile saved.'
    }
    Test-Case 'Opt-in Graph export preserves member and owner separately and round-trips all planes' {
        $result = Export-TestProfile -Planes @('AzureResource', 'Group', 'DirectoryRole')
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.PimGroupEligibilities.Count -eq 2 -and $data.DirectoryRoleEligibilities.Count -eq 1) 'Graph eligibility omitted.'
        Assert-True ($data.PimGroupEligibilities[0].EndDateTime -ne $data.PimGroupEligibilities[1].EndDateTime) 'Member/owner expiry collapsed.'
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $plan = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        Assert-True ($plan.Count -eq 4 -and @($plan | Where-Object { $_.Action -ne 'CREATE' }).Count -eq 0) 'Exported Graph entries cannot be previewed.'
        $null = Invoke-ProfileGrant -Rows $plan -Target $target
        Assert-True ($script:writes.Count -eq 4) 'Wrong number of mocked eligibility writes.'
        $ends = @($script:writes | Where-Object { $_.Body.accessId } | ForEach-Object { $_.Body.scheduleInfo.expiration.endDateTime } | Sort-Object -Unique)
        Assert-True ($ends.Count -eq 2) 'Graph grant lost member/owner expiration.'
    }
    Test-Case 'Requested Graph failure never leaves an Azure-only profile' {
        $script:mode = 'graph-denied'
        Assert-Throws { Export-TestProfile -Planes @('AzureResource', 'Group') }
        Assert-True (@(Get-ChildItem $tenant.ProfilesDir -Force).Count -eq 0) 'Partial cross-plane profile saved.'
    }
    Test-Case 'Wrong tenant export and wrong-tenant profile are refused' {
        $result = Export-TestProfile
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $tenant.TenantId = '88888888-8888-8888-8888-888888888888'
        Assert-Throws { Assert-ProfileSafe -Profile $prof -Tenant $tenant }
        Assert-Throws { Export-TestProfile -Key wrong }
    }
    Test-Case 'Policy read failure and changed policy block eligibility grants' {
        $null = Export-TestProfile
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $plan = @(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        $script:maximum = 'P1D'
        Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
        $res = Invoke-ProfileGrant -Rows $plan -Target $target
        Assert-True ($res.Fail -eq 1 -and $script:writes.Count -eq 0) 'Stale policy allowed a write.'
        $script:mode = 'unreadable-policy'
        $blocked=@(Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @())
        Assert-True ($blocked[0].Action -eq 'BLOCKED-ACTIVATION-POLICY' -and $blocked[0].ActivationCheck.Status -eq 'Unknown') 'Unreadable activation policy must be visible and blocked.'
    }
    Test-Case 'Expired dates and invalid durations are refused' {
        foreach ($duration in @('garbage', 'P0D', '-P1D')) { Assert-Throws { Export-TestProfile -Duration $duration } }
        Assert-Throws { New-CadmEligibilitySchedule -Entry @{ EndDateTime = '2000-01-01T00:00:00Z' } -MaxDuration P30D }
        Assert-Throws { New-CadmEligibilitySchedule -Entry @{ EndDateTime = $script:end; Duration = 'P1D' } -MaxDuration P30D }
    }
    Test-Case 'Launcher exports without TargetUser, Graph connection, or apply' {
        $mockAz = ${function:Invoke-AzJsonRaw}
        $mockRest = ${function:Invoke-Rest}
        $mockSetup = {
            Set-Item -Path Function:Invoke-AzJsonRaw -Value $mockAz
            Set-Item -Path Function:Invoke-Rest -Value $mockRest
            function Initialize-AzInvoker { }
            function Import-CadmTenant { Set-CadmTenant -TenantId $tenant.TenantId; return $tenant }
            function Resolve-CadmUser { return $source }
            function Connect-GraphIfNeeded { throw 'Unexpected Graph connection.' }
            function Read-Host { throw 'Unexpected prompt.' }
        }
        $text = Get-Content (Join-Path $root 'scripts/cadm/Invoke-CadmAccess.ps1') -Raw
        $text = $text.Replace(". (Join-Path " + '$PSScriptRoot' + " 'lib\CadmAccess.Core.ps1')", '. $core')
        $text = $text.Replace(". (Join-Path " + '$PSScriptRoot' + " 'lib\CadmProfile.ps1')", '. $profileLib')
        $text = $text.Replace(". (Join-Path " + '$PSScriptRoot' + " 'lib\CadmExport.ps1')", '. $exportLib; . $mockSetup')
        $text = $text.Replace('$PSScriptRoot', "'" + (Join-Path $root 'scripts/cadm').Replace("'", "''") + "'")
        # Keep launcher control flow; replace process exit so the test harness continues.
        $text = $text.Replace('exit 0', 'return')
        $entry = [scriptblock]::Create($text)
        & $entry -Mode export -SourceUser source@example.com -ProfileName launcher -ConnectGraph:$false
        Assert-True (Test-Path (Join-Path $tenant.ProfilesDir 'launcher.psd1')) 'Launcher did not export.'
        Assert-True ($script:writes.Count -eq 0) 'Launcher export wrote cloud access.'
        Assert-Throws { & $entry -Mode export -SourceUser source@example.com -ProfileName invalid -Apply }
    }
    Test-Case 'Target conditional and malformed eligibility reads block profile planning' {
        $null = Export-TestProfile
        $prof = @(Get-CadmProfiles -ProfilesDir $tenant.ProfilesDir)[0]
        $script:targetRows = @(@{ properties = @{ principalId = $target.id; scope = $script:scope; roleDefinitionId = $script:roleId; condition = 'restricted' } })
        Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
        $script:targetRows = @(@{ properties = @{ scope = $script:scope; roleDefinitionId = $script:roleId } })
        Assert-Throws { Resolve-ProfilePlan -Profile $prof -Target $target -Tenant $tenant -Subs @() }
        Assert-True ($script:writes.Count -eq 0) 'Incomplete target discovery wrote access.'
    }
    Test-Case 'Graph-only export does not scan Azure subscriptions' {
        function Get-Subscriptions { throw 'Unexpected Azure subscription scan.' }
        $result = Export-TestProfile -Planes @('Group', 'DirectoryRole')
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        Assert-True ($data.PimResourceEligibilities.Count -eq 0 -and $data.Export.SubscriptionIds.Count -eq 0) 'Graph-only export claims Azure coverage.'
    }
    Test-Case 'Export Graph sign-in requests only selected read scopes' {
        $ConnectGraph = $true; $UseDeviceCode = $false
        function Get-Module { return @{ Name = 'Microsoft.Graph.Authentication' } }
        function Import-Module { }
        function Test-MgConnected { return $false }
        function Connect-MgGraph { param($Scopes, $TenantId, $Environment, $ContextScope, $ErrorAction)
            $script:requested = @($Scopes)
            Assert-True ($TenantId -eq $script:ExpectedTenantId -and $Environment -eq 'Global') 'Wrong Graph authentication context.'
        }
        Connect-CadmExportGraph -Planes @('DirectoryRole')
        Assert-True ($script:requested.Count -eq 1 -and $script:requested[0] -eq 'RoleEligibilitySchedule.Read.Directory') 'Directory export requested unrelated scopes.'
        Connect-CadmExportGraph -Planes @('Group')
        Assert-True ($script:requested.Count -eq 2 -and @($script:requested | Where-Object { $_ -match 'Write|Directory' }).Count -eq 0) 'Group export requested write/directory scopes.'
        $ConnectGraph = $false
        function Connect-MgGraph { throw 'Unexpected sign-in.' }
        Connect-CadmExportGraph -Planes @('Group')
    }
    Test-Case 'Future source start dates remain future after export' {
        $script:sourceRows[0].properties.startDateTime = [datetimeoffset]::UtcNow.AddDays(2).ToString('o')
        $result = Export-TestProfile
        $data = Import-PowerShellDataFile -LiteralPath $result.Path
        $entry = $data.PimResourceEligibilities[0]
        $schedule = New-CadmEligibilitySchedule -Entry $entry -MaxDuration P30D
        Assert-True ($schedule.startDateTime -eq $script:sourceRows[0].properties.startDateTime) 'Future access was made immediately eligible.'
    }
    Write-Host "$script:passed export checks passed. Offline mocks only; no live cloud writes."
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($testBase, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'cadm-export-tests-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
