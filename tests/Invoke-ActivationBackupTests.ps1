#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1')
$script:passed=0
function Assert($value,[string]$message='Assertion failed'){if(-not $value){throw $message}}
function Refuses([scriptblock]$action){$refused=$false;try{&$action | Out-Null}catch{$refused=$true};Assert $refused 'Expected refusal'}
function Invoke-AzJsonRaw {throw 'Unexpected live CLI call'}
function Invoke-MgGraphRequest {throw 'Unexpected Graph call'}
function Assert-CadmScopeTenant {param($Scope)}
function Resolve-CadmEligibilityRole {param($RoleDefinitionId,$Scope) @{Id="/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionId";Guid=$RoleDefinitionId;Name='Owner'}}
$role='8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
$scope='/providers/Microsoft.Management/managementGroups/example'
$target=@{id='22222222-2222-2222-2222-222222222222'}
$entry=@{RoleDefinitionId=$role;Scope=$scope;Duration='P30D'}
$strict=@{ActivationRequirements=@{RequireMfa=$true;RequireApproval=$true;MaximumActivationDuration='PT2H'}}
$tenant=@{DefaultEligibilityDuration='P90D';ActivationRequirements=$strict.ActivationRequirements}
function Check($name,[scriptblock]$test){
    & {
        $script:rules=@(
            @{id='Expiration_Admin_Eligibility';maximumDuration='P90D'},
            @{id='Enablement_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};enabledRules=@('MultiFactorAuthentication')},
            @{id='Approval_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};setting=@{isApprovalRequired=$true;approvalStages=@(@{primaryApprovers=@(@{id='33333333-3333-3333-3333-333333333333';userType='Group'})})}},
            @{id='Expiration_EndUser_Assignment';target=@{caller='EndUser';level='Assignment';operations=@('All')};isExpirationRequired=$true;maximumDuration='PT2H'}
        )
        $script:mode='normal';$script:writes=0
        function Invoke-CadmRestAll {param($Url)
            if($script:mode -eq 'denied'){throw '403 policy denied'}
            if($Url -match 'roleManagementPolicyAssignments'){
                $record=@{properties=@{roleDefinitionId='8e3af657-a8ff-443c-a75c-2fe8c4bcb635';policyId='policy-id';effectiveRules=$script:rules}}
                if($script:mode -eq 'ambiguous'){return @($record,$record)}
                return @($record)
            }
            if($Url -match 'roleEligibilityScheduleInstances'){return @()}
            throw 'Unexpected read'
        }
        function Invoke-Rest {param($Url,$Method,$BodyFile)
            Assert ($Method -eq 'put' -and $Url -match 'roleEligibilityScheduleRequests') 'Unexpected mutation'
            $script:writes++;$script:LastAzError='';return @{id='mock-request'}
        }
        & $test
    }
    $script:passed++;Write-Host "PASS $name"
}
Check 'Explicit requirements enforce MFA approval and two-hour maximum' {
    $r=Get-CadmActivationRequirements $strict
    Assert ($r.RequireMfa -and $r.RequireApproval -and $r.MaximumActivationDuration -eq 'PT2H')
    $c=Get-CadmAzureActivationCheck $scope $role $r
    Assert ($c.Status -eq 'Pass' -and $c.PolicyFingerprint)
    Assert ($script:writes -eq 0)
}
Check 'Default reports Odyssey settings without imposing MFA approval or two-hour limit' {
    $script:rules[1].enabledRules=@()
    $script:rules[2].setting.isApprovalRequired=$false
    $script:rules[2].setting.approvalStages=@()
    $script:rules[3].maximumDuration='PT8H'
    foreach($config in @(@{},@{ActivationRequirements=@{}})){
        $r=Get-CadmActivationRequirements $config
        Assert (-not $r.RequireMfa -and -not $r.RequireApproval -and $null -eq $r.MaximumActivationDuration)
        $check=Get-CadmAzureActivationCheck $scope $role $r
        Assert ($check.Status -eq 'Observed' -and $check.Mode -eq 'ReportOnly')
        Assert (-not $check.MfaRequired -and -not $check.ApprovalRequired -and $check.MaximumActivationDuration -eq 'PT8H')
        $row=Resolve-CadmResourceEligibilityPlan $entry $target $config
        Assert ($row.Action -eq 'CREATE')
        Assert ($script:writes -eq 0)
    }
}
Check 'Tenant limits are configurable but malformed configuration is refused' {
    $r=Get-CadmActivationRequirements @{ActivationRequirements=@{MaximumActivationDuration='PT1H'}}
    Assert ((Get-CadmAzureActivationCheck $scope $role $r).Status -eq 'Fail')
    Refuses {Get-CadmActivationRequirements @{ActivationRequirements=@{RequireMfa='false'}}}
    Refuses {Get-CadmActivationRequirements @{ActivationRequirements=@{MaximumActivationDuration='PT0H'}}}
    Refuses {Get-CadmActivationRequirements @{ActivationRequirements=@{Typo=$true}}}
}
Check 'MFA is checked on end-user activation, not admin assignment' {
    $script:rules[1].enabledRules=@()
    $script:rules+=@{id='Enablement_Admin_Assignment';enabledRules=@('MultiFactorAuthentication')}
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Fail')
}
Check 'Authentication context alone is not claimed as proof of MFA' {
    $script:rules[1].enabledRules=@()
    $script:rules+=@{id='AuthenticationContext_EndUser_Assignment';isEnabled=$true;claimValue='c1'}
    $c=Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)
    Assert ($c.Status -eq 'Fail' -and $c.AuthenticationContextEnabled)
}
Check 'Disabled approval fails an explicitly configured approval requirement' {
    $script:rules[2].setting.isApprovalRequired=$false
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Fail')
}
Check 'Approval without named primary approvers fails' {
    $script:rules[2].setting.approvalStages[0].primaryApprovers=@()
    $c=Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)
    Assert ($c.Status -eq 'Fail' -and -not $c.ApproversConfigured)
}
Check 'Malformed approval flags are Unknown, not coerced to true' {
    $script:rules[2].setting.isApprovalRequired='false'
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Unknown')
}
Check 'Long or unbounded activation fails independently of eligibility term' {
    $script:rules[3].maximumDuration='PT8H'
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Fail')
    $script:rules[3].maximumDuration='PT1H';$script:rules[3].isExpirationRequired=$false
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Fail')
}
Check 'Missing duplicate or wrong-target rules remain Unknown' {
    $script:rules[1].target.caller='Admin'
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Unknown')
    $script:rules[1].target.caller='EndUser';$script:rules+=,$script:rules[1]
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Unknown')
    $script:rules=@($script:rules | Where-Object id -ne 'Approval_EndUser_Assignment')
    Assert ((Get-CadmAzureActivationCheck $scope $role (Get-CadmActivationRequirements $strict)).Status -eq 'Unknown')
}
Check 'Unreadable and ambiguous policies produce blocked preview rows' {
    foreach($mode in @('denied','ambiguous')){
        $script:mode=$mode
        $row=Resolve-CadmResourceEligibilityPlan $entry $target $tenant
        Assert ($row.Action -eq 'BLOCKED-ACTIVATION-POLICY' -and $row.ActivationCheck.Status -eq 'Unknown')
    }
    Assert ($script:writes -eq 0)
}
Check 'Changed policy is detected in plan fingerprints' {
    $before=Resolve-CadmResourceEligibilityPlan $entry $target $tenant
    $script:rules[3].maximumDuration='PT1H'
    $after=Resolve-CadmResourceEligibilityPlan $entry $target $tenant
    Assert ((Get-CadmPlanFingerprint @($before)) -cne (Get-CadmPlanFingerprint @($after)))
}
Check 'Unsafe policy change after preview prevents grant at the sink' {
    $row=Resolve-CadmResourceEligibilityPlan $entry $target $tenant
    Assert ($row.Action -eq 'CREATE')
    $script:rules[1].enabledRules=@()
    Refuses {Invoke-CadmResourceEligibilityGrant -Item $row -Target $target}
    Assert ($script:writes -eq 0)
}
Check 'Safe policy allows an eligibility request but never activation or policy writes' {
    $row=Resolve-CadmResourceEligibilityPlan $entry $target $tenant
    $receipt=Invoke-CadmResourceEligibilityGrant -Item $row -Target $target
    Assert ($script:writes -eq 1 -and $receipt.RequestId -match 'roleEligibilityScheduleRequests')
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cadm-backup-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $temp 'profiles') | Out-Null
$tenantFile=Join-Path $temp 'tenant.psd1';$profileFile=Join-Path $temp 'profiles/test.psd1'
[IO.File]::WriteAllText($tenantFile,"# configuration comments"+[Environment]::NewLine+"@{TenantId='example'}")
[IO.File]::WriteAllText($profileFile,"# preserve this comment"+[Environment]::NewLine+"@{Name='Version one'}")
$backupTenant=@{Path=$tenantFile;ProfilesDir=(Join-Path $temp 'profiles');TenantId='example'}
Check 'Local snapshot preserves comments bytes and source files with verified manifest hashes' {
    $before=[IO.File]::ReadAllBytes($profileFile)
    $b=Backup-CadmProfileFiles -Tenant $backupTenant -ProfilePaths @($profileFile) -Reason 'Test'
    $manifest=Get-Content -LiteralPath $b.ManifestPath -Raw | ConvertFrom-Json
    Assert ($manifest.State -eq 'Complete' -and $manifest.Files.Count -eq 2)
    foreach($file in $manifest.Files){Assert ((Get-CadmFileHash (Join-Path $b.Path $file.BackupFile)) -eq $file.Sha256)}
    Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($profileFile)) -ceq [Convert]::ToBase64String($before))
    Assert ((Get-Content (Join-Path $b.Path 'profile-test.psd1') -Raw) -match 'preserve this comment')
    Assert ($script:writes -eq 0)
}
Check 'Repeated backups never overwrite earlier versions' {
    $first=Backup-CadmProfileFiles -Tenant $backupTenant -ProfilePaths @($profileFile)
    [IO.File]::WriteAllText($profileFile,"@{Name='Version two'}")
    $second=Backup-CadmProfileFiles -Tenant $backupTenant -ProfilePaths @($profileFile)
    Assert ($first.Path -ne $second.Path)
    Assert ((Get-Content (Join-Path $first.Path 'profile-test.psd1') -Raw) -match 'Version one')
    Assert ((Get-Content (Join-Path $second.Path 'profile-test.psd1') -Raw) -match 'Version two')
}
Check 'Backup rejects unrelated paths and missing source files' {
    Refuses {Backup-CadmProfileFiles -Tenant $backupTenant -ProfilePaths @($tenantFile)}
    Refuses {Backup-CadmProfileFiles -Tenant $backupTenant -ProfilePaths @((Join-Path $temp 'profiles/missing.psd1'))}
}
Write-Host "$script:passed activation and local backup checks passed. Offline mocks only."
