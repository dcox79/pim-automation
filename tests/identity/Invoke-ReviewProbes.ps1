#requires -Version 5.1
<#
Historical review probes. Fixed paths now report refusals; remaining P2 paths still demonstrate gaps.
No tenant connection or grant is performed. All API boundaries are replaced with mocks.
Run: pwsh -NoProfile -File tests/identity/Invoke-ReviewProbes.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$core = Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1'
$profiles = Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1'

function Invoke-Probe {
    param([string]$Name, [scriptblock]$Check)
    & {
        . $core
        . $profiles
        # Any unexpected cloud operation fails locally.
        function Invoke-AzJson { throw 'Unexpected Azure call in offline probe' }
        function Invoke-Rest { throw 'Unexpected REST call in offline probe' }
        function Invoke-MgJson { throw 'Unexpected Graph call in offline probe' }
        function Invoke-MgGraphRequest { throw 'Unexpected Graph SDK call in offline probe' }
        function Get-GroupsFor { return @() }
        $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
        function Write-Host { }
        $target = @{ id = 'synthetic-target'; accountEnabled = $true }
        $tenant = @{ ScopeTokens = @{ 'example-scope' = '/subscriptions/22222222-2222-2222-2222-222222222222' } }
        try { $observed = & $Check } catch { $observed = "BLOCKED: $($_.Exception.Message)" }
        [pscustomobject]@{ Probe = $Name; Observed = $observed }
    }
}

$results = @(
    Invoke-Probe 'Role GUID bypasses standing Owner name restriction' {
        # Public built-in role identifier, not tenant data.
        $p = @{ Name = 'Synthetic'; Data = @{ Rbac = @(@{
            Role = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; Scope = 'example-scope'
        }) } }
        Assert-ProfileSafe -Profile $p -Tenant $tenant
        'ACCEPTED'
    }
    Invoke-Probe 'Scope alias bypasses root scope restriction' {
        $tenant.ScopeTokens['example-scope'] = '/'
        $p = @{ Name = 'Synthetic'; Data = @{ Rbac = @(@{ Role = 'Reader'; Scope = 'example-scope' }) } }
        Assert-ProfileSafe -Profile $p -Tenant $tenant
        Resolve-CadmScope -Scope 'example-scope' -Tenant $tenant
    }
    Invoke-Probe 'Standing group membership never checks PIM enrollment' {
        function Resolve-GroupByName {
            @{ id = 'synthetic-pim-group'; displayName = 'Synthetic PIM group';
               onPremisesSyncEnabled = $false; isAssignableToRole = $false }
        }
        function Invoke-Rest { @{ id = 'synthetic-pim-group'; isAssignableToRole = $false; onPremisesSyncEnabled = $false; groupTypes = @() } }
        function Invoke-MgJsonAll { @{ Ok = $true; Value = @(@{ id = 'synthetic-policy' }) } }
        $p = @{ Data = @{ GroupMemberships = @(@{ Group = 'Synthetic PIM group' }) } }
        (Resolve-ProfilePlan -Profile $p -Target $target -Tenant $tenant -Subs @()).Action
    }
    Invoke-Probe 'Denied RBAC read becomes a CREATE plan' {
        function Resolve-CadmStandingRole { return '33333333-3333-3333-3333-333333333333' }
        function Invoke-AzJson { $script:LastAzError = 'AuthorizationFailed'; return $null }
        $p = @{ Data = @{ Rbac = @(@{ Role = 'Reader'; Scope = 'example-scope' }) } }
        (Resolve-ProfilePlan -Profile $p -Target $target -Tenant $tenant -Subs @()).Action
    }
    Invoke-Probe 'Failed active group read still reports complete PIM state' {
        function Invoke-MgJsonAll {
            param($Uri)
            if ($Uri -match '/assignmentScheduleInstances') {
                return @{ Ok = $false; Value = @(); Error = 'Forbidden' }
            }
            @{ Ok = $true; Value = @(); Error = '' }
        }
        $r = Get-PimGroupsFor -PrincipalId 'synthetic-target'
        "Ok=$($r.Ok); activeCount=$($r.ActiveGroupIds.Count)"
    }
    Invoke-Probe 'Throttled Azure activation read does not mark state unknown' {
        function Invoke-Rest { $script:LastAzError = '429 TooManyRequests'; return $null }
        $r = Get-PimActivatedFor -PrincipalId 'synthetic-target' -Subs @(@{ Id = 'synthetic-sub' })
        "Denied=$($r.Denied); activationCount=$($r.Map.Count)"
    }
    Invoke-Probe 'Existing Graph context accepted without tenant comparison' {
        function Get-MgContext { [pscustomobject]@{ TenantId = 'different-tenant'; Scopes = @('User.Read.All') } }
        "Connected=$(Test-MgConnected)"
    }
    Invoke-Probe 'Subscription inventory retains multiple tenants' {
        function Assert-CadmAzContext { }
        function Invoke-AzJson {
            @(@{ id = 'sub-a'; name = 'Synthetic A'; tenantId = '11111111-1111-1111-1111-111111111111'; environmentName = 'AzureCloud' },
              @{ id = 'sub-b'; name = 'Synthetic B'; tenantId = '44444444-4444-4444-4444-444444444444'; environmentName = 'AzureCloud' })
        }
        "SubscriptionCount=$(@(Get-Subscriptions).Count)"
    }
    Invoke-Probe 'Explicit group duration bypasses policy ceiling' {
        function Get-PimGroupExpirationRule { @{ MaxDuration = 'P30D' } }
        (Resolve-PimGroupExpiration -GroupId 'synthetic-pim-group' -Duration 'P365D').duration
    }
    Invoke-Probe 'Graph pagination cap reports incomplete results as successful' {
        function Invoke-MgJson { @{ Ok = $true; Value = @(); Next = 'synthetic-next-page'; Error = '' } }
        $r = Invoke-MgJsonAll -Uri 'synthetic-first-page'
        "Ok=$($r.Ok)"
    }
    Invoke-Probe 'Fresh apply connection drops directory scopes and fragments group scopes' {
        $script:ExpectedTenantId = '11111111-1111-1111-1111-111111111111'
        $Apply = $true
        $ConnectGraph = $true
        $UseDeviceCode = $true
        $MgScopeList = @($MgWriteScopeList + $MgDirWriteScopeList)
        $script:probeContext = $null
        $script:probeRequestedScopes = @()
        function Get-Module { return $true }
        function Import-Module { }
        function Get-MgContext { return $script:probeContext }
        function Test-MgPlaneUsable { return $true }
        function Connect-MgGraph {
            [CmdletBinding()]
            param([string[]]$Scopes, [switch]$UseDeviceCode, [string]$TenantId, [string]$Environment, [string]$ContextScope)
            $script:probeRequestedScopes = $Scopes
            $script:probeContext = [pscustomobject]@{ Account = 'synthetic@example.com'; Scopes = $Scopes; TenantId = $TenantId; Environment = $Environment }
        }
        Connect-GraphIfNeeded -ProbePrincipalId 'synthetic-target'
        "Requested=$($script:probeRequestedScopes -join ',')"
    }
)
$results | ConvertTo-Json -Depth 5
