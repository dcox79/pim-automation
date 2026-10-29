#requires -Version 5.1
# Guided workflow helpers. Cloud writes remain in the existing profile engine.
function Get-WorkflowFileHash {
    param([string]$Path)
    $stream=[IO.File]::OpenRead($Path);$algorithm=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','') }
    finally {$algorithm.Dispose();$stream.Dispose()}
}
function Resolve-WorkflowUser {
    param([string]$Reference)
    if ($Reference -notmatch '^[0-9a-fA-F-]{36}$' -and $Reference -notmatch '^[^\s@]+@[^\s@]+$') {
        throw 'Use the exact UPN or object ID; account prefixes are not accepted.'
    }
    $u = Resolve-CadmUser -Ref $Reference
    if ($Reference -match '@' -and $u.userPrincipalName -ine $Reference) { throw 'Exact account lookup did not match.' }
    if ($Reference -notmatch '@' -and $u.id -ine $Reference) { throw 'Object ID did not match.' }
    if (-not $u.accountEnabled) { throw 'Account is disabled or its enabled state is unreadable.' }
    return $u
}
function Set-WorkflowScope {
    param([hashtable]$Tenant, [string]$ScopeToken)
    if (-not $ScopeToken -or -not $Tenant.ScopeTokens.ContainsKey($ScopeToken) -or $ScopeToken -eq 'template-scope') {
        throw 'Choose a configured tenant scope token.'
    }
    $resolved = Resolve-CadmScope -Scope $ScopeToken -Tenant $Tenant
    $Tenant.ScopeTokens['template-scope'] = $resolved
    return $resolved
}
function Assert-WorkflowMetadata {
    param($Data, [switch]$ForApply)
    $m = $Data.Metadata
    if (-not $m) { throw 'Template metadata is missing. Use the builder or update metadata first.' }
    foreach ($key in @('SchemaVersion','Version','Owner','Purpose','ReviewDate','Status')) {
        if ([string]::IsNullOrWhiteSpace([string]$m[$key])) { throw "Missing template metadata: $key" }
    }
    if ($m.SchemaVersion -ne '1' -or $m.Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Unsupported schema or invalid semantic version.' }
    if ($m.Status -notin @('Draft','Reviewed')) { throw 'Template status must be Draft or Reviewed.' }
    $date = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$m.ReviewDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) { throw 'ReviewDate must be yyyy-MM-dd.' }
    if ($ForApply -and ($date.Date -lt [datetime]::UtcNow.Date -or $m.Status -ne 'Reviewed' -or -not $m.Reviewer)) {
        throw 'Apply requires a Reviewed template, reviewer, and an unexpired review date.'
    }
}
function Save-WorkflowTemplate {
    param([hashtable]$Data, [string]$Key, [hashtable]$Tenant)
    if ($Key -notmatch '^[a-z][a-z0-9-]{0,63}$' -or $Key -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])$') { throw 'Invalid template filename key.' }
    $allowed = @('Name','Description','Metadata','Rbac','GroupMemberships','PimResourceEligibilities','PimGroupEligibilities','DirectoryRoleEligibilities','Export')
    foreach ($k in $Data.Keys) { if ($k -notin $allowed) { throw "Unknown template key: $k" } }
    Assert-WorkflowMetadata $Data
    Assert-ProfileSafe -Profile @{Name=$Data.Name;Data=$Data} -Tenant $Tenant
    $count=0
    foreach($plane in @('Rbac','GroupMemberships','PimResourceEligibilities','PimGroupEligibilities','DirectoryRoleEligibilities')) { $count+=@(Get-ProfileEntries $Data[$plane]).Count }
    if(-not $count){throw 'An empty template cannot be saved.'}
    $seen = @{}
    foreach ($entry in @(Get-ProfileEntries $Data.PimResourceEligibilities)) {
        foreach ($k in $entry.Keys) { if ($k -notin @('RoleDefinitionId','Scope','Duration','StartDateTime','EndDateTime','SourceEndDateTime')) { throw "Unknown resource eligibility key: $k" } }
        $identity = "$($entry.RoleDefinitionId)|$(Resolve-CadmScope $entry.Scope $Tenant)".ToLowerInvariant()
        if ($seen.ContainsKey($identity)) { throw 'Duplicate role/scope in template.' }; $seen[$identity] = $true
    }
    $path = Join-Path $Tenant.ProfilesDir "$Key.psd1"
    $literal = ConvertTo-CadmPsdLiteral $Data
    # CreateNew is atomic and never overwrites another template.
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = [Text.UTF8Encoding]::new($true).GetBytes($literal); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    return $path
}
function Get-WorkflowFingerprint {
    param($Rows)
    $items = @($Rows | ForEach-Object {
        # Exclude computed start timestamps, retain actual policy-bounded duration/end date.
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $_.Plane,$_.Action,$_.Item,$_.Scope,$_.RoleDefinitionId,$_.AccessId,$_.ScheduleInfo.expiration.duration,$_.ScheduleInfo.expiration.endDateTime,$_.Detail
    } | Sort-Object)
    return ($items -join "`n")
}
function Get-WorkflowPlan {
    param($Profile,$Target,$Tenant,$Subs)
    $rows=@(Resolve-ProfilePlan -Profile $Profile -Target $Target -Tenant $Tenant -Subs $Subs)
    foreach($row in $rows) {
        if($row.Action -eq 'CREATE' -and $row.Plane -in @('PIM-GRP','PIM-DIR')) {
            # Resolve the policy-bounded term before the operator confirms, on all PIM planes.
            $row.ScheduleInfo=Get-CadmProfileGraphSchedule -Entry $row -Plane $row.Plane -DefaultDuration $Tenant.DefaultEligibilityDuration
        }
    }
    return $rows
}
function Get-WorkflowResourceReport {
    param($Rows, $Target, [int]$RenewalDays = 30)
    $out = @()
    foreach ($scope in @($Rows | Where-Object Plane -eq 'PIM-RES' | Select-Object -ExpandProperty Scope -Unique)) {
        Assert-CadmScopeTenant -Scope $scope
        $url = "$ArmBase$scope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=$PimApi&`$filter=principalId%20eq%20'$($Target.id)'"
        $all = @(Invoke-CadmRestAll -Url $url)
        $expected = @($Rows | Where-Object { $_.Plane -eq 'PIM-RES' -and $_.Scope -ieq $scope })
        foreach ($record in $all) {
            $p = Get-CadmField $record 'properties'
            if ($p.principalId -ine $Target.id -or $p.scope -ine $scope) { continue }
            $rid = Get-RoleDefGuid $p.roleDefinitionId
            $matches = @($expected | Where-Object RoleDefinitionId -eq $rid)
            $end = if ($p.endDateTime) { ConvertTo-CadmEligibilityDate $p.endDateTime } else { $null }
            $start = if ($p.startDateTime) { ConvertTo-CadmEligibilityDate $p.startDateTime } else { $null }
            $out += [pscustomobject]@{
                AssignmentId=$record.id; RoleDefinitionId=$rid; Scope=$p.scope; Status=$p.status
                StartDateTime=$p.startDateTime; EndDateTime=$p.endDateTime
                Classification=$(if (-not $matches.Count) {'Extra'} elseif ($end -and $end -le [datetimeoffset]::UtcNow) {'Expired'} elseif ($start -and $start -gt [datetimeoffset]::UtcNow) {'Scheduled'} elseif ($end -and $end -le [datetimeoffset]::UtcNow.AddDays($RenewalDays)) {'Expiring'} else {'Present'})
                Conditional=(Test-CadmConditionalAssignment $p)
            }
        }
    }
    return $out
}
function Get-WorkflowVerification {
    param($Rows, $Target, $Profile, $Tenant, $Subs)
    $results = @()
    $resource = @(); $resourceError = $null; $fresh = @(); $planError = $null
    try { $resource = @(Get-WorkflowResourceReport -Rows $Rows -Target $Target) } catch { $resourceError = $_.Exception.Message }
    try { $fresh = @(Resolve-ProfilePlan -Profile $Profile -Target $Target -Tenant $Tenant -Subs $Subs) } catch { $planError = $_.Exception.Message }
    foreach ($row in $Rows) {
        $status = 'Pending'; $detail = 'Not observed yet'; $evidence = @()
        if ($row.Plane -eq 'PIM-RES') {
            if ($resourceError) { $status='Unknown'; $detail=$resourceError }
            else {
                $evidence = @($resource | Where-Object { $_.RoleDefinitionId -eq $row.RoleDefinitionId -and $_.Scope -ieq $row.Scope })
                if (@($evidence | Where-Object { -not $_.Conditional -and $_.Status -eq 'Provisioned' -and $_.Classification -in @('Present','Expiring','Scheduled') }).Count) { $status='Provisioned'; $detail='Azure schedule instance read back' }
                elseif (@($evidence | Where-Object Status -in @('Failed','Denied','Canceled','Revoked')).Count) { $status='Failed'; $detail='Azure returned a failed or revoked schedule' }
            }
        } elseif ($planError) { $status='Unknown'; $detail=$planError }
        else {
            $match = @($fresh | Where-Object { $_.Plane -eq $row.Plane -and $_.Item -eq $row.Item -and $_.Scope -ieq $row.Scope -and $_.Action -eq 'SKIP-EXISTS' })
            if ($match.Count) { $status='Observed'; $detail='Existing assignment observed by profile discovery; provisioning status not exposed by this reader' }
        }
        $results += [pscustomobject]@{Plane=$row.Plane;Role=$row.Item;Scope=$row.Scope;Status=$status;Detail=$detail;Evidence=$evidence}
    }
    return $results
}
function Write-WorkflowJson {
    param($Value,[string]$Path)
    $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding utf8
}
