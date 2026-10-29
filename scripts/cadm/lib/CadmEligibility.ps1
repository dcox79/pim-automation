#requires -Version 5.1
# Profile eligibility helpers, loaded after the shared core.
function ConvertTo-CadmEligibilityDate {
    param($Value)
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).ToUniversalTime() }
    $text = [string]$Value
    $date = [datetimeoffset]::MinValue
    if ($text -notmatch '(Z|[+-]\d{2}:\d{2})$' -or -not [datetimeoffset]::TryParse($text,
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) {
        throw 'Eligibility dates must be valid ISO dates with an explicit timezone.'
    }
    return $date.ToUniversalTime()
}
function Assert-CadmEligibilityTiming {
    param($Entry)
    $duration = [string](Get-CadmField $Entry 'Duration')
    $end = Get-CadmField $Entry 'EndDateTime'
    if ($duration -and $end) { throw 'Specify Duration or EndDateTime, not both.' }
    if ($duration) {
        $span = ConvertTo-CadmTimeSpan $duration
        if (-not $span -or $span -le [timespan]::Zero) { throw 'Eligibility Duration must be a positive ISO-8601 duration.' }
    }
    $start = [datetimeoffset]::UtcNow
    if (Get-CadmField $Entry 'StartDateTime') {
        $requested = ConvertTo-CadmEligibilityDate $Entry.StartDateTime
        if ($requested -gt $start) { $start = $requested }
    }
    if ($end -and (ConvertTo-CadmEligibilityDate $end) -le $start) { throw 'Eligibility expiry must be later than its start and the current time.' }
}
function New-CadmEligibilitySchedule {
    param($Entry, [string]$MaxDuration, [string]$DefaultDuration = 'P365D')
    Assert-CadmEligibilityTiming $Entry
    $maximum = ConvertTo-CadmTimeSpan $MaxDuration
    if (-not $maximum -or $maximum -le [timespan]::Zero) { throw 'Eligibility policy maximum duration is missing or unreadable.' }
    $start = [datetimeoffset]::UtcNow
    if (Get-CadmField $Entry 'StartDateTime') {
        $requested = ConvertTo-CadmEligibilityDate $Entry.StartDateTime
        if ($requested -gt $start) { $start = $requested }
    }
    if (Get-CadmField $Entry 'EndDateTime') {
        $end = ConvertTo-CadmEligibilityDate $Entry.EndDateTime
        if (($end - $start) -gt $maximum) { throw 'Exported expiry exceeds the target eligibility policy maximum duration.' }
        $expiration = @{ type = 'afterDateTime'; endDateTime = $end.ToString('o') }
    } else {
        $duration = [string](Get-CadmField $Entry 'Duration')
        if (-not $duration) { $duration = Select-CadmDuration -MaxDuration $MaxDuration -DefaultDuration $DefaultDuration }
        $span = ConvertTo-CadmTimeSpan $duration
        if (-not $span -or $span -le [timespan]::Zero -or $span -gt $maximum) { throw 'Requested eligibility duration exceeds policy or is invalid.' }
        $expiration = @{ type = 'afterDuration'; duration = $duration }
    }
    return @{ startDateTime = $start.ToString('o'); expiration = $expiration }
}
function Resolve-CadmEligibilityRole {
    param([string]$RoleDefinitionId, [string]$Scope)
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($RoleDefinitionId, [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Resource eligibility requires a role-definition GUID.' }
    Assert-CadmScopeTenant -Scope $Scope
    $defs = @(Invoke-AzJson -AzArgs @('role', 'definition', 'list', '--name', $guid.ToString(), '--scope', $Scope, '-o', 'json'))
    if ($script:LastAzError -or $defs.Count -ne 1 -or -not $defs[0]) { throw 'Cannot uniquely resolve the eligible Azure role.' }
    $def = $defs[0]
    $id = [string](Get-CadmField $def 'id')
    if ($id -notmatch '/providers/Microsoft.Authorization/roleDefinitions/[0-9a-fA-F-]{36}$' -or
        (Get-RoleDefGuid $id) -ine $guid.ToString()) { throw 'Resolved eligibility role ID differs from the profile.' }
    return @{ Id = $id; Guid = $guid.ToString(); Name = [string](Get-CadmField $def 'roleName') }
}
function Get-CadmResourceEligibilityPolicy {
    param([string]$Scope, [string]$RoleDefinitionId)
    $policies = @(Invoke-CadmRestAll -Url "$ArmBase$Scope/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=$PimApi")
    $matches = @($policies | Where-Object {
        (Get-RoleDefGuid ([string](Get-CadmField (Get-CadmField $_ 'properties') 'roleDefinitionId'))) -ieq $RoleDefinitionId
    })
    if ($matches.Count -ne 1) { throw 'Cannot uniquely determine the Azure eligibility policy.' }
    $rules = @(Get-CadmField (Get-CadmField $matches[0] 'properties') 'effectiveRules')
    $expiration = @($rules | Where-Object { (Get-CadmField $_ 'id') -eq 'Expiration_Admin_Eligibility' })
    if ($expiration.Count -ne 1) { throw 'Azure eligibility expiration policy is missing.' }
    return [string](Get-CadmField $expiration[0] 'maximumDuration')
}
function Resolve-CadmResourceEligibilityPlan {
    param($Entry, $Target, [hashtable]$Tenant)
    if (Test-CadmConditionalAssignment $Entry) { throw 'Conditional resource eligibility profiles are not supported.' }
    $scope = Resolve-CadmScope -Scope ([string]$Entry.Scope) -Tenant $Tenant
    $role = Resolve-CadmEligibilityRole -RoleDefinitionId $Entry.RoleDefinitionId -Scope $scope
    $default = [string](Get-CadmField $Tenant 'DefaultEligibilityDuration')
    if (-not $default) { $default = 'P365D' }
    $schedule = New-CadmEligibilitySchedule -Entry $Entry -DefaultDuration $default -MaxDuration (Get-CadmResourceEligibilityPolicy -Scope $scope -RoleDefinitionId $role.Guid)
    $filter = "principalId eq '$($Target.id)'"
    $existing = @(Invoke-CadmRestAll -Url "$ArmBase$scope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=$PimApi&`$filter=$filter")
    foreach ($record in $existing) {
        $p = Get-CadmField $record 'properties'
        $existingRole = [guid]::Empty
        if (-not $p -or (Get-CadmField $p 'principalId') -ine $Target.id -or
            -not (Get-CadmField $p 'scope') -or
            -not [guid]::TryParse((Get-RoleDefGuid ([string](Get-CadmField $p 'roleDefinitionId'))), [ref]$existingRole) -or
            $existingRole -eq [guid]::Empty) { throw 'Malformed target eligibility response; planning is incomplete.' }
    }
    $found = @($existing | Where-Object {
        $p = Get-CadmField $_ 'properties'
        (Get-CadmField $p 'principalId') -ieq $Target.id -and (Get-CadmField $p 'scope') -ieq $scope -and
        (Get-RoleDefGuid ([string](Get-CadmField $p 'roleDefinitionId'))) -ieq $role.Guid
    })
    if (@($found | Where-Object { Test-CadmConditionalAssignment (Get-CadmField $_ 'properties') }).Count) { throw 'Existing conditional eligibility cannot be replaced by an unconditional profile.' }
    return [pscustomobject]@{
        Plane = 'PIM-RES'; Action = $(if ($found.Count) { 'SKIP-EXISTS' } else { 'CREATE' })
        Item = $role.Name; Scope = $scope; RoleDefinitionId = $role.Guid; ArmRoleDefinitionId = $role.Id
        Detail = $(if ($found.Count) { 'Existing eligibility retained; no renewal or expiry change.' } else { 'Azure-resource eligibility only' })
        Duration = [string](Get-CadmField $Entry 'Duration'); EndDateTime = Get-CadmField $Entry 'EndDateTime'
        StartDateTime = Get-CadmField $Entry 'StartDateTime'; ScheduleInfo = $schedule
    }
}
function Invoke-CadmResourceEligibilityGrant {
    param($Item, $Target, [string]$Justification, [string]$TicketNumber, [string]$TicketSystem, [string]$DefaultDuration = 'P365D')
    # Recheck role, scope, policy, dates, and existing eligibility before writing.
    $fresh = Resolve-CadmResourceEligibilityPlan -Entry $Item -Target $Target -Tenant @{ DefaultEligibilityDuration = $DefaultDuration }
    if ($fresh.Action -eq 'SKIP-EXISTS') { return }
    $properties = @{
        principalId = $Target.id; roleDefinitionId = $fresh.ArmRoleDefinitionId
        requestType = 'AdminAssign'; justification = $Justification; scheduleInfo = $fresh.ScheduleInfo
    }
    if ($TicketNumber -or $TicketSystem) { $properties.ticketInfo = @{ ticketNumber = $TicketNumber; ticketSystem = $TicketSystem } }
    $bodyFile = Join-Path ([IO.Path]::GetTempPath()) "pim-profile-$([guid]::NewGuid()).json"
    try {
        @{ properties = $properties } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $bodyFile -Encoding utf8
        $url = "$ArmBase$($fresh.Scope)/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$([guid]::NewGuid())?api-version=$PimApi"
        $null = Invoke-Rest -Url $url -Method put -BodyFile $bodyFile
        if ($script:LastAzError) { throw $script:LastAzError }
    } finally {
        if (Test-Path -LiteralPath $bodyFile) { Remove-Item -LiteralPath $bodyFile -ErrorAction SilentlyContinue }
    }
}
function Resolve-CadmProfileGroup {
    param($Entry)
    $id = [string](Get-CadmField $Entry 'GroupId')
    if (-not $id) { return Resolve-GroupByName -Name ([string]$Entry.Group) }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($id, [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Invalid profile GroupId.' }
    $r = Invoke-MgJson -Uri "$GraphBase/groups/$($guid.ToString())"
    if (-not $r.Ok -or (Get-CadmField $r.Value 'id') -ine $id) { throw "Cannot read profile group $id. $($r.Error)" }
    return $r.Value
}
function Resolve-CadmProfileDirectoryRole {
    param($Entry)
    $id = [string](Get-CadmField $Entry 'RoleDefinitionId')
    if (-not $id) { return Resolve-DirectoryRoleId -Name ([string]$Entry.Role) }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($id, [ref]$guid) -or $guid -eq [guid]::Empty) { throw 'Invalid directory role-definition ID.' }
    $r = Invoke-MgJson -Uri "$GraphBase/roleManagement/directory/roleDefinitions/$($guid.ToString())"
    if (-not $r.Ok) { return @{ Ok = $false; Id = ''; Error = $r.Error } }
    if ((Get-CadmField $r.Value 'id') -ine $id) { throw 'Directory role-definition ID mismatch.' }
    return @{ Ok = $true; Id = $id; Name = [string](Get-CadmField $r.Value 'displayName'); Error = '' }
}
function Get-CadmProfileGraphSchedule {
    param($Entry, [string]$Plane, [string]$DefaultDuration = 'P365D')
    if ($Plane -eq 'PIM-GRP') { $rule = Get-PimGroupExpirationRule -GroupId $Entry.Scope -AccessId $Entry.AccessId }
    else { $rule = Get-DirRoleExpirationRule -RoleDefinitionId $Entry.RoleDefinitionId }
    return New-CadmEligibilitySchedule -Entry $Entry -MaxDuration ([string](Get-CadmField $rule 'MaxDuration')) -DefaultDuration $DefaultDuration
}
