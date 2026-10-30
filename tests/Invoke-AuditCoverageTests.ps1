#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmExport.ps1')
$script:passed=0
function Assert($value,[string]$why='Assertion failed'){if(-not $value){throw $why}}
function Refuses([scriptblock]$test){$thrown=$false;try{&$test|Out-Null}catch{$thrown=$true};Assert $thrown 'Expected refusal'}
function Invoke-AzJsonRaw {throw 'Unexpected CLI call in offline test'}
function Invoke-MgGraphRequest {throw 'Unexpected Graph call in offline test'}
function Assert-CadmScopeTenant {param($Scope)}
function Assert-CadmAzContext {}
function Assert-CadmGraphContext {}
$script:ExpectedTenantId='11111111-1111-1111-1111-111111111111'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cadm-audit-tests-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null
function Check($Name,[scriptblock]$Test){
    & {
        $target=@{id='22222222-2222-2222-2222-222222222222';userPrincipalName='user@example.com'}
        $scope='/providers/Microsoft.Management/managementGroups/example'
        $role='8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $start=[datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
        $end=[datetimeoffset]::UtcNow.AddDays(10).ToString('o')
        $row=[pscustomobject]@{Plane='PIM-RES';Action='CREATE';Item='Owner';Scope=$scope;RoleDefinitionId=$role;ScheduleInfo=@{startDateTime=$start;expiration=@{type='afterDateTime';endDateTime=$end}}}
        $p=@{principalId=$target.id;scope=$scope;roleDefinitionId=$role;status='Provisioned';startDateTime=$start;endDateTime=$end}
        $script:records=@(@{id='schedule-id';properties=$p})
        $script:graph=@()
        function Invoke-CadmRestAll {param($Url) return $script:records}
        function Invoke-MgJsonAll {param($Uri) return @{Ok=$true;Value=$script:graph}}
        & $Test
    }
    $script:passed++;Write-Host "PASS $Name"
}
Check 'Exact resource role, scope, and dates verified' {
    $v=@(Get-CadmProfileVerification @($row) $target);Assert ($v[0].Status -eq 'Verified')
    Assert ($v[0].Evidence[0].AssignmentId -eq 'schedule-id')
}
Check 'Longer expiry is a mismatch, never verified' {
    $p.endDateTime=[datetimeoffset]::UtcNow.AddDays(11).ToString('o')
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Mismatch')
}
Check 'Shifted start is a mismatch' {
    $p.startDateTime=[datetimeoffset]::UtcNow.AddHours(1).ToString('o')
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Mismatch')
}
Check 'A future schedule verifies only with the requested dates' {
    $p.startDateTime=[datetimeoffset]::UtcNow.AddDays(1).ToString('o');$row.ScheduleInfo.startDateTime=$p.startDateTime
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Verified')
}
foreach($field in @('principalId','scope','roleDefinitionId')){
    Check "Wrong $field is not the requested assignment" {
        $p[$field]='different'
        Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Pending')
    }
}
Check 'Pending and denied Azure responses never verify' {
    $p.status='PendingApproval';Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Pending')
    $p.status='Denied';Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Failed')
}
Check 'Conditions and duplicates never verify as an exact grant' {
    $p.condition='restriction';Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Mismatch')
    $p.Remove('condition');$script:records+=@{id='other';properties=$p}
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Mismatch')
}
Check 'Failed or malformed reads remain Unknown' {
    $p.Remove('principalId');Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Unknown')
    function Invoke-CadmRestAll {param($Url) throw '403 read denied'}
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Unknown')
}
Check 'Existing eligibility is retained with its actual expiry' {
    $row.Action='SKIP-EXISTS';$p.endDateTime=[datetimeoffset]::UtcNow.AddDays(2).ToString('o')
    $v=Get-CadmProfileVerification @($row) $target
    Assert ($v.Status -eq 'Retained');Assert ($v.Evidence[0].EndDateTime -eq $p.endDateTime)
}
foreach($plane in @('PIM-GRP','PIM-DIR')){
    Check "$plane reads exact eligibility and expiry" {
        $row.Plane=$plane
        $row | Add-Member NoteProperty AccessId 'member'
        $record=@{id='graph-instance';principalId=$target.id;startDateTime=$start;endDateTime=$end}
        if($plane -eq 'PIM-GRP'){$row.Scope='group-id';$record.groupId='group-id';$record.accessId='member'}
        else{$row.Scope='/';$record.directoryScopeId='/';$record.roleDefinitionId=$role}
        $script:graph=@($record)
        Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Verified')
        $record.endDateTime=$null
        Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Mismatch')
    }
}
Check 'Group ownership cannot satisfy member eligibility' {
    $row.Plane='PIM-GRP';$row.Scope='group-id';$row | Add-Member NoteProperty AccessId 'member'
    $script:graph=@(@{id='owner';principalId=$target.id;groupId='group-id';accessId='owner';startDateTime=$start;endDateTime=$end})
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Pending')
}
Check 'Direct standing membership is verified independently of transitive membership' {
    $row.Plane='GROUP';$row.Scope='group-id'
    $script:graph=@(@{id='other-user'})
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Pending')
    $script:graph=@(@{id=$target.id})
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Verified')
}
Check 'Standing RBAC checks exact principal role and scope' {
    $row.Plane='RBAC';$row | Add-Member NoteProperty Detail $role
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Verified')
    $p.scope='/subscriptions/other'
    Assert ((Get-CadmProfileVerification @($row) $target).Status -eq 'Pending')
}
Check 'Audit preserves submissions, failures, evidence, identity and event timestamps' {
    $run=Join-Path $temp ([guid]::NewGuid());New-Item -ItemType Directory $run|Out-Null
    $script:grantCalls=0
    function Invoke-ProfileGrant {
        param($Rows,$Target,$Justification,$DefaultDuration,$TicketNumber,$TicketSystem)
        $script:grantCalls++
        $disk=Get-Content (Join-Path $run 'submissions.json') -Raw | ConvertFrom-Json
        Assert ($disk.Entries[$script:grantCalls-1].State -eq 'Submitting') 'Write occurred before journal flush'
        if($script:grantCalls -eq 2){throw 'simulated request failure'}
        return @{Ok=1;Fail=0;Requests=@(@{RequestId='receipt-id'});Entries=@(@{State='Submitted';ScheduleInfo=$row.ScheduleInfo})}
    }
    $other=[pscustomobject]@{Plane='PIM-RES';Action='CREATE';Item='Other';Scope=$scope;RoleDefinitionId='different';ScheduleInfo=$row.ScheduleInfo}
    $out=Invoke-CadmAuditedProfileApply -Rows @($row,$other) -Target $target -RunDirectory $run -Context @{RunId='test';Actor='operator';TenantId=$script:ExpectedTenantId;TemplateHash='hash';TemplateVersion='1.0.0'} -VerificationAttempts 1 -VerificationDelaySeconds 0
    Assert ($out.State -eq 'Partial');Assert ($out.Submission.Entries.Count -eq 2)
    Assert ($out.Submission.Entries[0].Receipt.Requests[0].RequestId -eq 'receipt-id')
    Assert ($out.Submission.Entries[1].Error -match 'simulated')
    $disk=Get-Content (Join-Path $run 'outcome.json') -Raw | ConvertFrom-Json
    Assert ($disk.Context.Actor -eq 'operator');Assert ($disk.Submission.Entries[0].Events[-1].TimestampUtc)
    Assert ($disk.Verification[0].Status -eq 'Verified')
}
Check 'Read-back failure preserves successful request receipt without claiming success' {
    $run=Join-Path $temp ([guid]::NewGuid());New-Item -ItemType Directory $run|Out-Null
    function Invoke-ProfileGrant {param($Rows,$Target,$Justification,$DefaultDuration,$TicketNumber,$TicketSystem) @{Ok=1;Fail=0;Requests=@(@{RequestId='accepted'});Entries=@(@{State='Submitted';ScheduleInfo=$row.ScheduleInfo})}}
    function Invoke-CadmRestAll {param($Url) throw 'read failed'}
    $out=Invoke-CadmAuditedProfileApply @($row) $target -RunDirectory $run -Context @{RunId='test'} -VerificationAttempts 1
    Assert ($out.State -eq 'PendingOrUnknown')
    Assert ($out.Submission.Entries[0].Receipt.Requests[0].RequestId -eq 'accepted')
}
Check 'Bounded retries observe eventual provisioning' {
    $run=Join-Path $temp ([guid]::NewGuid());New-Item -ItemType Directory $run|Out-Null
    $script:reads=0
    function Invoke-ProfileGrant {param($Rows,$Target,$Justification,$DefaultDuration,$TicketNumber,$TicketSystem) @{Ok=1;Fail=0;Entries=@(@{State='Submitted';ScheduleInfo=$row.ScheduleInfo})}}
    function Invoke-CadmRestAll {param($Url) $script:reads++;if($script:reads -ge 2){$script:records}}
    $out=Invoke-CadmAuditedProfileApply @($row) $target -RunDirectory $run -Context @{RunId='test'} -VerificationAttempts 3 -VerificationDelaySeconds 0
    Assert ($out.State -eq 'Verified');Assert ($script:reads -eq 2)
}
Check 'Retained-only run verifies without any grant calls' {
    $run=Join-Path $temp ([guid]::NewGuid());New-Item -ItemType Directory $run|Out-Null
    $row.Action='SKIP-EXISTS'
    function Invoke-ProfileGrant {throw 'Should never write'}
    $out=Invoke-CadmAuditedProfileApply @($row) $target -RunDirectory $run -Context @{RunId='test'} -VerificationAttempts 1
    Assert ($out.State -eq 'Verified');Assert ($out.Verification[0].Status -eq 'Retained')
}
Check 'Descriptions explain actual role, root scope and preserved expiry' {
    $data=@{PimResourceEligibilities=@(@{Role='Owner';Scope="/providers/Microsoft.Management/managementGroups/$script:ExpectedTenantId";EndDateTime=$end});PimGroupEligibilities=@();DirectoryRoleEligibilities=@()}
    $text=Get-CadmExportDescription $data @{TenantId=$script:ExpectedTenantId}
    Assert ($text -match 'Eligible Owner at tenant root management group')
    Assert ($text -match 'UTC' -and $text -match 'Requires PIM activation')
}
Check 'Management group discovery works without subscriptions and validates all scopes' {
    $script:records=@(@{id=$scope})
    $scopes=@(Get-CadmExportScopes -Tenant @{} -Subscriptions @() -IncludeManagementGroups -AdditionalScopes $scope)
    Assert ($scopes.Count -eq 1 -and $scopes[0] -eq $scope)
    function Invoke-CadmRestAll {throw 'management group read denied'}
    Refuses {Get-CadmExportScopes -Tenant @{} -IncludeManagementGroups}
}
Check 'Group-derived evidence keeps current and eligible membership paths separate' {
    $g='33333333-3333-3333-3333-333333333333'
    $eligible='44444444-4444-4444-4444-444444444444'
    $owner='55555555-5555-5555-5555-555555555555'
    $script:graph=@(@{'@odata.type'='#microsoft.graph.group';id=$g;displayName='Nested membership'})
    function Invoke-CadmRestAll {param($Url)
        $id=if([uri]::UnescapeDataString($Url) -match '44444444-4444-4444-4444-444444444444'){'44444444-4444-4444-4444-444444444444'}else{'33333333-3333-3333-3333-333333333333'}
        @(@{id="assignment-$id";properties=@{principalId=$id;roleDefinitionId=$role;scope=$scope;endDateTime=$end;condition='preserve me'}})
    }
    $coverage=Get-CadmGroupDerivedCoverage -Source $target -Scopes @($scope) -Planes @('AzureResource') -EligibleGroups @(@{GroupId=$eligible;AccessId='member';EndDateTime=$end},@{GroupId=$owner;AccessId='owner'})
    Assert ($coverage.Groups.Count -eq 2)
    Assert (@($coverage.Groups | Where-Object GroupId -eq $owner).Count -eq 0)
    Assert (@($coverage.Assignments | Where-Object Path -eq 'EligibleMembership').Count -gt 0)
    Assert ($coverage.Assignments[0].Condition -eq 'preserve me')
}
Check 'Failed group reads cannot become a partial success export' {
    function Invoke-MgJsonAll {param($Uri) @{Ok=$false;Error='403';Value=@()}}
    Refuses {Get-CadmGroupDerivedCoverage -Source $target -Scopes @($scope) -Planes @('AzureResource')}
}
Check 'Evidence-only export writes no grant template' {
    $tenant=@{TenantId=$script:ExpectedTenantId;ProfilesDir=$temp;ScopeTokens=@{};DefaultEligibilityDuration='P30D'}
    function Get-Subscriptions { @() }
    function Invoke-CadmRestAll {param($Url) @()}
    $script:graph=@()
    $out=Export-CadmEligibilityProfile -Source $target -Tenant $tenant -ProfileName 'evidence-only' -AdditionalScopes $scope -IncludeGroupDerivedAccess
    Assert (-not $out.Path);Assert (Test-Path -LiteralPath $out.CoveragePath)
    Assert (-not (Test-Path (Join-Path $temp 'evidence-only.psd1')))
}
Check 'Management group at-nextLink pagination follows every page' {
    # Exercise the real paging helper, with only its HTTP transport mocked.
    . (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
    function Invoke-Rest {param($Url)
        $script:LastAzError=''
        if($Url -eq 'first'){@{value=@(@{id='one'});'@nextLink'='second'}}
        else{@{value=@(@{id='two'})}}
    }
    Assert (@(Invoke-CadmRestAll 'first').Count -eq 2)
}
Write-Host "$script:passed audit and coverage checks passed. Offline mocks only."
