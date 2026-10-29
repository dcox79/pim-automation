#requires -Version 5.1
# Read-only cloud export; the only mutation is one tenant-local data file.
function ConvertTo-CadmPsdLiteral {
    param($Value, [int]$Indent = 0)
    $pad = ' ' * $Indent
    $nl = [Environment]::NewLine
    if ($null -eq $Value) { return '$null' }
    if ($Value -is [bool]) { if ($Value) { return '$true' }; return '$false' }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = @('@{')
        foreach ($key in $Value.Keys) {
            $parts += "$pad    '$(([string]$key).Replace("'", "''"))' = $(ConvertTo-CadmPsdLiteral -Value $Value[$key] -Indent ($Indent + 4))"
        }
        return ($parts + "$pad}") -join $nl
    }
    if ($Value -is [System.Collections.IList]) {
        if (-not $Value.Count) { return '@()' }
        $parts = @($Value | ForEach-Object { "$pad    $(ConvertTo-CadmPsdLiteral -Value $_ -Indent ($Indent + 4))" })
        return "@($nl" + ($parts -join ",$nl") + "$nl$pad)"
    }
    return "'$(([string]$Value).Replace("'", "''"))'"
}
function Add-CadmExportTiming {
    param([System.Collections.IDictionary]$Entry, $Record, [string]$Duration, [string]$DefaultDuration)
    if ($Record -is [System.Collections.IDictionary]) { $hasEnd = $Record.Contains('endDateTime') }
    else { $hasEnd = $null -ne $Record.PSObject.Properties['endDateTime'] }
    if (-not $hasEnd) { throw 'Eligibility response is missing endDateTime.' }
    $end = Get-CadmField $Record 'endDateTime'
    $start = Get-CadmField $Record 'startDateTime'
    if ($start) {
        $startDate = ConvertTo-CadmEligibilityDate $start
        if ($startDate -gt [datetimeoffset]::UtcNow) { $Entry.StartDateTime = $startDate.ToString('o') }
    }
    if ($end) {
        $endDate = ConvertTo-CadmEligibilityDate $end
        if ($endDate -le [datetimeoffset]::UtcNow) { throw 'An expired source eligibility was returned; refresh discovery before exporting.' }
        $Entry.SourceEndDateTime = $endDate.ToString('o')
        if (-not $Duration) { $Entry.EndDateTime = $endDate.ToString('o') }
    }
    if ($Duration) { $Entry.Duration = $Duration }
    elseif (-not $end) { $Entry.Duration = $DefaultDuration }
    Assert-CadmEligibilityTiming $Entry
}
function Add-CadmExportEntry {
    param([System.Collections.IDictionary]$Map, [string]$Key, $Entry)
    $keyLower = $Key.ToLowerInvariant()
    if ($Map.Contains($keyLower)) {
        if (($Map[$keyLower] | ConvertTo-Json -Depth 8 -Compress) -cne ($Entry | ConvertTo-Json -Depth 8 -Compress)) {
            throw "Multiple eligibility schedules differ for $Key; review them before exporting."
        }
    } else { $Map[$keyLower] = $Entry }
}
function Export-CadmEligibilityProfile {
    param($Source, [hashtable]$Tenant, [string]$ProfileName,
          [ValidateSet('AzureResource', 'Group', 'DirectoryRole')][string[]]$Planes = @('AzureResource'),
          [string]$Duration)
    if ($ProfileName -notmatch '^[a-z0-9][a-z0-9-]{0,63}$' -or $ProfileName -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])$') {
        throw 'ProfileName must be a non-reserved filename key: 1-64 letters, digits, or hyphens.'
    }
    $sourceGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Source.id, [ref]$sourceGuid) -or $sourceGuid -eq [guid]::Empty) { throw 'A resolved source user ID is required.' }
    if (-not $Planes.Count) { throw 'Select at least one eligibility plane.' }
    if ($Tenant.TenantId -ine $script:ExpectedTenantId) { throw 'Export tenant differs from the bound session.' }
    Assert-CadmAzContext
    $destination = Join-Path $Tenant.ProfilesDir "$ProfileName.psd1"
    if (Test-Path -LiteralPath $destination) { throw "Profile already exists: $destination. Choose a new ProfileName." }
    $default = [string](Get-CadmField $Tenant 'DefaultEligibilityDuration')
    if (-not $default) { $default = 'P365D' }
    Assert-CadmEligibilityTiming @{ Duration = $(if ($Duration) { $Duration } else { $default }) }
    $resource = [ordered]@{}; $group = [ordered]@{}; $directory = [ordered]@{}
    $subscriptionIds = @(); $verifiedScopes = @{}
    $filter = "principalId eq '$($sourceGuid.ToString())'"
    if ($Planes -contains 'AzureResource') {
        $subs = @(Get-Subscriptions)
        if (-not $subs.Count) { throw 'No accessible subscriptions: Azure-resource coverage cannot be established.' }
        $subscriptionIds = @($subs | ForEach-Object { $_.Id } | Sort-Object -Unique)
        Start-Phase "Export Azure eligibilities ($($subs.Count) subscriptions)"
        foreach ($sub in $subs) {
            Step-Phase
            $url = '{0}/subscriptions/{1}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={2}&$filter={3}' -f $ArmBase, $sub.Id, $PimApi, $filter
            $values = @(Invoke-CadmRestAll -Url $url)
            foreach ($record in $values) {
                $p = Get-CadmField $record 'properties'
                if (-not $p -or (Get-CadmField $p 'principalId') -ine $Source.id) { throw 'Unexpected principal or malformed Azure eligibility response.' }
                if (Test-CadmConditionalAssignment $p) { throw 'Conditional Azure eligibilities cannot be exported without losing restrictions.' }
                $scope = Resolve-CadmScope -Scope ([string](Get-CadmField $p 'scope')) -Tenant $Tenant
                if (-not $verifiedScopes.ContainsKey($scope)) { Assert-CadmScopeTenant -Scope $scope; $verifiedScopes[$scope] = $true }
                $role = Get-RoleDefGuid ([string](Get-CadmField $p 'roleDefinitionId'))
                $roleGuid = [guid]::Empty
                if (-not [guid]::TryParse($role, [ref]$roleGuid) -or $roleGuid -eq [guid]::Empty) { throw 'Malformed source role-definition ID.' }
                $label = Get-CadmField (Get-CadmField (Get-CadmField $p 'expandedProperties') 'roleDefinition') 'displayName'
                $entry = [ordered]@{ RoleDefinitionId = $roleGuid.ToString(); Role = $(if ($label) { [string]$label } else { $roleGuid.ToString() }); Scope = $scope }
                Add-CadmExportTiming -Entry $entry -Record $p -Duration $Duration -DefaultDuration $default
                Add-CadmExportEntry -Map $resource -Key "$role|$scope" -Entry $entry
            }
        }
        End-Phase
    }
    if ($Planes -contains 'Group') {
        Assert-CadmGraphContext
        $url = '{0}/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter={1}' -f $GraphBase, $filter
        $result = Invoke-MgJsonAll -Uri $url
        if (-not $result.Ok) { throw "Group eligibility export is incomplete: $($result.Error)" }
        foreach ($e in $result.Value) {
            $gid = [guid]::Empty
            if ((Get-CadmField $e 'principalId') -ine $Source.id -or
                -not [guid]::TryParse([string](Get-CadmField $e 'groupId'), [ref]$gid) -or $gid -eq [guid]::Empty -or
                (Get-CadmField $e 'accessId') -notin @('member', 'owner')) { throw 'Malformed group eligibility response.' }
            $entry = [ordered]@{ GroupId = $gid.ToString(); AccessId = [string]$e.accessId }
            Add-CadmExportTiming -Entry $entry -Record $e -Duration $Duration -DefaultDuration $default
            Add-CadmExportEntry -Map $group -Key "$gid|$($e.accessId)" -Entry $entry
        }
    }
    if ($Planes -contains 'DirectoryRole') {
        Assert-CadmGraphContext
        $url = '{0}/roleManagement/directory/roleEligibilityScheduleInstances?$filter={1}' -f $GraphBase, $filter
        $result = Invoke-MgJsonAll -Uri $url
        if (-not $result.Ok) { throw "Directory-role eligibility export is incomplete: $($result.Error)" }
        foreach ($e in $result.Value) {
            $rid = [guid]::Empty
            if ((Get-CadmField $e 'principalId') -ine $Source.id -or
                -not [guid]::TryParse([string](Get-CadmField $e 'roleDefinitionId'), [ref]$rid) -or $rid -eq [guid]::Empty) { throw 'Malformed directory eligibility response.' }
            if ((Get-CadmField $e 'directoryScopeId') -ne '/' -or (Get-CadmField $e 'appScopeId')) { throw 'Administrative-unit or app-scoped directory eligibility export is not supported.' }
            $entry = [ordered]@{ RoleDefinitionId = $rid.ToString(); DirectoryScopeId = '/' }
            Add-CadmExportTiming -Entry $entry -Record $e -Duration $Duration -DefaultDuration $default
            Add-CadmExportEntry -Map $directory -Key "$rid|/" -Entry $entry
        }
    }
    if (($resource.Count + $group.Count + $directory.Count) -eq 0) { throw 'No eligible assignments found in the selected discovery coverage; no profile written.' }
    $data = [ordered]@{
        Name = $ProfileName
        Description = 'Exported eligibility template. Review scopes, expiry, and activation policies before applying.'
        Export = [ordered]@{
            SchemaVersion = '1'; TenantId = $Tenant.TenantId; SourceUserId = $Source.id
            SourceUserPrincipalName = $Source.userPrincipalName; GeneratedUtc = [datetimeoffset]::UtcNow.ToString('o')
            Planes = @($Planes | Sort-Object -Unique); SubscriptionIds = $subscriptionIds
            Coverage = 'Direct user eligibility in selected planes; Azure scopes discovered through accessible subscriptions. Not a complete effective-access inventory.'
            ExpiryMode = $(if ($Duration) { 'FreshDuration' } else { 'PreserveSourceExpiry; permanent source becomes bounded tenant default' })
        }
        Rbac = @(); GroupMemberships = @()
        PimResourceEligibilities = @($resource.Keys | Sort-Object | ForEach-Object { $resource[$_] })
        PimGroupEligibilities = @($group.Keys | Sort-Object | ForEach-Object { $group[$_] })
        DirectoryRoleEligibilities = @($directory.Keys | Sort-Object | ForEach-Object { $directory[$_] })
    }
    Assert-ProfileSafe -Profile @{ Name = $ProfileName; Data = $data } -Tenant $Tenant
    $text = '# Generated from live eligibility reads. Review before applying; no access was granted.' + [Environment]::NewLine + (ConvertTo-CadmPsdLiteral $data) + [Environment]::NewLine
    if (-not (Test-Path -LiteralPath $Tenant.ProfilesDir)) { New-Item -ItemType Directory -Path $Tenant.ProfilesDir -Force | Out-Null }
    $temporary = Join-Path $Tenant.ProfilesDir ".$([guid]::NewGuid()).tmp.psd1"
    try {
        [IO.File]::WriteAllText($temporary, $text, [Text.UTF8Encoding]::new($true))
        $loaded = Import-PowerShellDataFile -LiteralPath $temporary
        Assert-ProfileSafe -Profile @{ Name = $ProfileName; Data = $loaded } -Tenant $Tenant
        [IO.File]::Move($temporary, $destination)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue }
    }
    return [pscustomobject]@{ Path = $destination; AzureResource = $resource.Count; Group = $group.Count; DirectoryRole = $directory.Count }
}


function Connect-CadmExportGraph {
    param([string[]]$Planes)
    if (-not $ConnectGraph) { return }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication or export AzureResource only.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if (Test-MgConnected) { return }
    $scopes = @()
    if ($Planes -contains 'Group') { $scopes += @('PrivilegedEligibilitySchedule.Read.AzureADGroup', 'Group.Read.All') }
    if ($Planes -contains 'DirectoryRole') { $scopes += 'RoleEligibilitySchedule.Read.Directory' }
    $parameters = @{ TenantId = $script:ExpectedTenantId; Environment = 'Global'; ContextScope = 'Process'; Scopes = $scopes; ErrorAction = 'Stop' }
    if ($UseDeviceCode) { $parameters.UseDeviceCode = $true }
    Connect-MgGraph @parameters | Out-Null
}
