#requires -Version 5.1
<#
Offline review probes. These demonstrate CURRENT gaps, not successful safety checks.
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
        function Write-Host { }
        $target = @{ id = 'synthetic-target'; accountEnabled = $true }
        $tenant = @{ ScopeTokens = @{ 'example-scope' = '/subscriptions/synthetic' } }
        $observed = & $Check
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
        function Get-PimGroupsFor { throw 'PIM enrollment was checked' }
        $p = @{ Data = @{ GroupMemberships = @(@{ Group = 'Synthetic PIM group' }) } }
        (Resolve-ProfilePlan -Profile $p -Target $target -Tenant $tenant -Subs @()).Action
    }
    Invoke-Probe 'Denied RBAC read becomes a CREATE plan' {
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
        function Invoke-AzJson {
            @(@{ id = 'sub-a'; name = 'Synthetic A'; tenantId = 'tenant-a' },
              @{ id = 'sub-b'; name = 'Synthetic B'; tenantId = 'tenant-b' })
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
            param([string[]]$Scopes, [switch]$UseDeviceCode)
            $script:probeRequestedScopes = $Scopes
            $script:probeContext = [pscustomobject]@{ Account = 'synthetic@example.com'; Scopes = $Scopes }
        }
        Connect-GraphIfNeeded -ProbePrincipalId 'synthetic-target'
        "Requested=$($script:probeRequestedScopes -join ',')"
    }
)
$results | ConvertTo-Json -Depth 5
