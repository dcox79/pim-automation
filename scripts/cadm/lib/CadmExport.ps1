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
          [string]$Duration, [string[]]$AdditionalScopes, [switch]$IncludeManagementGroups, [switch]$IncludeGroupDerivedAccess)
    if ($ProfileName -notmatch '^[a-z0-9][a-z0-9-]{0,63}$' -or $ProfileName -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])$') {
        throw 'ProfileName must be a non-reserved filename key: 1-64 letters, digits, or hyphens.'
    }
    $sourceGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Source.id, [ref]$sourceGuid) -or $sourceGuid -eq [guid]::Empty) { throw 'A resolved source user ID is required.' }
    if (-not $Planes.Count) { throw 'Select at least one eligibility plane.' }
    if(($AdditionalScopes.Count -or $IncludeManagementGroups) -and $Planes -notcontains 'AzureResource'){throw 'ARM scope options require the AzureResource plane.'}
    if ($Tenant.TenantId -ine $script:ExpectedTenantId) { throw 'Export tenant differs from the bound session.' }
    Assert-CadmAzContext
    $destination = Join-Path $Tenant.ProfilesDir "$ProfileName.psd1"
    if (Test-Path -LiteralPath $destination) { throw "Profile already exists: $destination. Choose a new ProfileName." }
    $default = [string](Get-CadmField $Tenant 'DefaultEligibilityDuration')
    if (-not $default) { $default = 'P365D' }
    Assert-CadmEligibilityTiming @{ Duration = $(if ($Duration) { $Duration } else { $default }) }
    $resource = [ordered]@{}; $group = [ordered]@{}; $directory = [ordered]@{}
    $subscriptionIds = @(); $verifiedScopes = @{}; $discoveryScopes=@()
    $filter = "principalId eq '$($sourceGuid.ToString())'"
    if ($Planes -contains 'AzureResource') {
        $subs = @(Get-Subscriptions)
        $discoveryScopes=@(Get-CadmExportScopes -Tenant $Tenant -Subscriptions $subs -AdditionalScopes $AdditionalScopes -IncludeManagementGroups:$IncludeManagementGroups)
        if (-not $discoveryScopes.Count) { throw 'No accessible subscriptions or requested scopes: Azure-resource coverage cannot be established.' }
        $subscriptionIds = @($subs | ForEach-Object { $_.Id } | Sort-Object -Unique)
        Start-Phase "Export Azure eligibilities ($($discoveryScopes.Count) scopes)"
        foreach ($discoveryScope in $discoveryScopes) {
            Step-Phase
            $url = '{0}{1}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={2}&$filter={3}' -f $ArmBase, $discoveryScope, $PimApi, $filter
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
    $groupCoverage=if($IncludeGroupDerivedAccess){Get-CadmGroupDerivedCoverage -Source $Source -Scopes $discoveryScopes -Planes $Planes -EligibleGroups @($group.Values)}else{@{Coverage='Not requested';Groups=@();Assignments=@()}}
    if (($resource.Count + $group.Count + $directory.Count) -eq 0) {
        if($IncludeGroupDerivedAccess){
            if(-not (Test-Path -LiteralPath $Tenant.ProfilesDir)){New-Item -ItemType Directory -Path $Tenant.ProfilesDir -Force | Out-Null}
            $reportPath=Join-Path $Tenant.ProfilesDir "$ProfileName.coverage.json"
            if(Test-Path -LiteralPath $reportPath){throw "Coverage report already exists: $reportPath"}
            $report=@{SourceUserId=$Source.id;TenantId=$Tenant.TenantId;GeneratedUtc=[datetimeoffset]::UtcNow.ToString('o');Planes=$Planes;QueriedScopes=$discoveryScopes;GroupDerivedAccess=$groupCoverage;DirectEligibilityCount=0}
            # Evidence-only exports do not create a misleading empty grant template.
            $stream=[IO.File]::Open($reportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$bytes=[Text.UTF8Encoding]::new($true).GetBytes(($report | ConvertTo-Json -Depth 30));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
            return [pscustomobject]@{Path=$null;CoveragePath=$reportPath;AzureResource=0;Group=0;DirectoryRole=0}
        }
        throw 'No eligible assignments found in the selected discovery coverage; no profile written.'
    }
    $data = [ordered]@{
        Name = $ProfileName
        Description = ''
        Export = [ordered]@{
            SchemaVersion = '1'; TenantId = $Tenant.TenantId; SourceUserId = $Source.id
            SourceUserPrincipalName = $Source.userPrincipalName; GeneratedUtc = [datetimeoffset]::UtcNow.ToString('o')
            Planes = @($Planes | Sort-Object -Unique); SubscriptionIds = $subscriptionIds
            QueriedScopes=$discoveryScopes; ManagementGroupDiscovery=[bool]$IncludeManagementGroups; GroupDerivedAccess=$groupCoverage
            Coverage = 'Direct user eligibility in selected planes at recorded discovery scopes. Optional group-derived evidence is informational and never becomes direct grants. Not a complete effective-access inventory.'
            ExpiryMode = $(if ($Duration) { 'FreshDuration' } else { 'PreserveSourceExpiry; permanent source becomes bounded tenant default' })
        }
        Rbac = @(); GroupMemberships = @()
        PimResourceEligibilities = @($resource.Keys | Sort-Object | ForEach-Object { $resource[$_] })
        PimGroupEligibilities = @($group.Keys | Sort-Object | ForEach-Object { $group[$_] })
        DirectoryRoleEligibilities = @($directory.Keys | Sort-Object | ForEach-Object { $directory[$_] })
    }
    $data.Description=Get-CadmExportDescription -Data $data -Tenant $Tenant
    $labels=@($data.PimResourceEligibilities | ForEach-Object {$_.Role} | Sort-Object -Unique)
    if($labels.Count -eq 1 -and -not $group.Count -and -not $directory.Count){$data.Name="$($Tenant.Name) $($labels[0]) via PIM".Trim()}
    else{$data.Name=($ProfileName -replace '-', ' ')+' - PIM eligibility'}
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
    param([string[]]$Planes, [switch]$IncludeGroupDerivedAccess)
    if (-not $ConnectGraph) { return }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication or export AzureResource only.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if (Test-MgConnected) { return }
    $scopes = @()
    if ($Planes -contains 'Group') { $scopes += @('PrivilegedEligibilitySchedule.Read.AzureADGroup', 'Group.Read.All') }
    if ($Planes -contains 'DirectoryRole') { $scopes += 'RoleEligibilitySchedule.Read.Directory' }
    if($IncludeGroupDerivedAccess){$scopes+='User.Read.All';if($Planes -contains 'DirectoryRole'){$scopes+='RoleManagement.Read.Directory'}}
    $parameters = @{ TenantId = $script:ExpectedTenantId; Environment = 'Global'; ContextScope = 'Process'; Scopes = $scopes; ErrorAction = 'Stop' }
    if ($UseDeviceCode) { $parameters.UseDeviceCode = $true }
    Connect-MgGraph @parameters | Out-Null
}


function Get-CadmExportScopes {
    param([hashtable]$Tenant, [object[]]$Subscriptions, [string[]]$AdditionalScopes, [switch]$IncludeManagementGroups)
    $scopes=@($Subscriptions | ForEach-Object {"/subscriptions/$($_.Id)"})
    foreach($scope in $AdditionalScopes){$scopes+=Resolve-CadmScope -Scope $scope -Tenant $Tenant}
    if($IncludeManagementGroups){
        $groups=@(Invoke-CadmRestAll -Url "$ArmBase/providers/Microsoft.Management/managementGroups?api-version=2020-05-01")
        foreach($group in $groups){
            $scope=Resolve-CadmScope -Scope ([string]$group.id) -Tenant $Tenant
            if($scope -notmatch '^/providers/Microsoft.Management/managementGroups/'){throw 'Malformed management-group discovery response.'}
            $scopes+=$scope
        }
    }
    foreach($scope in @($scopes | Sort-Object -Unique)){Assert-CadmScopeTenant -Scope $scope; $scope}
}
function Get-CadmExportDescription {
    param($Data, [hashtable]$Tenant)
    $parts=@()
    foreach($entry in $Data.PimResourceEligibilities){
        $label=if($entry.Role){$entry.Role}else{$entry.RoleDefinitionId}
        $scope=$entry.Scope
        if($scope -eq "/providers/Microsoft.Management/managementGroups/$($Tenant.RootManagementGroupId)" -or $scope -eq "/providers/Microsoft.Management/managementGroups/$($Tenant.TenantId)"){$where='tenant root management group'}
        elseif($scope -match '/managementGroups/([^/]+)$'){$where="management group $($Matches[1])"}
        elseif($scope -match '^/subscriptions/([^/]+)$'){$where="subscription $($Matches[1])"}
        else{$where=$scope}
        $parts+="Eligible $label at $where"
    }
    foreach($entry in $Data.PimGroupEligibilities){$parts+="Eligible group $($entry.AccessId) for $($entry.GroupId)"}
    foreach($entry in $Data.DirectoryRoleEligibilities){$parts+="Eligible directory role $($entry.RoleDefinitionId) at tenant scope"}
    $all=@($Data.PimResourceEligibilities)+@($Data.PimGroupEligibilities)+@($Data.DirectoryRoleEligibilities)
    $terms=@($all | ForEach-Object {
        if($_.EndDateTime){'expires '+(ConvertTo-CadmEligibilityDate $_.EndDateTime).ToString('yyyy-MM-dd HH:mm:ss')+' UTC'}
        else{"duration $($_.Duration) from assignment"}
    } | Sort-Object -Unique)
    $text=if($parts.Count -le 3){$parts -join '; '}else{"$($Data.PimResourceEligibilities.Count) Azure role, $($Data.PimGroupEligibilities.Count) group, and $($Data.DirectoryRoleEligibilities.Count) directory-role eligibilities"}
    $termText=if($terms.Count -eq 1){$terms[0]}else{'separate expiry dates or durations per entry'}
    return "$text; $termText. Requires PIM activation."
}
function Get-CadmGroupDerivedCoverage {
    # Evidence only: never turn a group's permissions into a direct user grant.
    param($Source,[string[]]$Scopes,[string[]]$Planes,$EligibleGroups)
    Assert-CadmGraphContext
    $membership=Invoke-MgJsonAll -Uri ('{0}/users/{1}/transitiveMemberOf?$select=id,displayName' -f $GraphBase,$Source.id)
    if(-not $membership.Ok){throw "Group membership coverage is incomplete: $($membership.Error)"}
    $groups=@{}
    foreach($g in $membership.Value){
        if(-not (Get-CadmField $g '@odata.type')){throw 'Membership object type is missing.'}
        if((Get-CadmField $g '@odata.type') -ne '#microsoft.graph.group'){continue}
        $id=[guid]::Empty
        if(-not [guid]::TryParse([string]$g.id,[ref]$id) -or $id -eq [guid]::Empty){throw 'Malformed group membership response.'}
        $groups[$id.ToString()]=@{GroupId=$id.ToString();Name=$g.displayName;Path='CurrentTransitiveMembership'}
    }
    foreach($g in $EligibleGroups){
        # Ownership does not itself make the user a member of the group.
        if($g.AccessId -eq 'member' -and -not $groups.ContainsKey($g.GroupId)){
            $groups[$g.GroupId]=@{GroupId=$g.GroupId;Name=$null;Path='EligibleMembership';MembershipEndDateTime=$g.EndDateTime}
        }
    }
    $observations=@()
    foreach($g in $groups.Values){
        $filter=[uri]::EscapeDataString("principalId eq '$($g.GroupId)'")
        if($Planes -contains 'AzureResource'){
            foreach($scope in $Scopes){
                foreach($kind in @('roleEligibilityScheduleInstances','roleAssignments')){
                    $version=if($kind -eq 'roleAssignments'){'2022-04-01'}else{$PimApi}
                    $records=@(Invoke-CadmRestAll -Url ('{0}{1}/providers/Microsoft.Authorization/{2}?api-version={3}&$filter={4}' -f $ArmBase,$scope,$kind,$version,$filter))
                    foreach($record in $records){
                        $p=$record.properties
                        if($p.principalId -ine $g.GroupId -or -not $p.scope -or -not $p.roleDefinitionId){throw 'Malformed group-derived Azure assignment.'}
                        Assert-CadmScopeTenant -Scope $p.scope
                        $observations+=@{Plane='AzureResource';Kind=$kind;GroupId=$g.GroupId;Path=$g.Path;AssignmentId=$record.id;RoleDefinitionId=$p.roleDefinitionId;Scope=$p.scope;StartDateTime=$p.startDateTime;EndDateTime=$p.endDateTime;Condition=$p.condition;ConditionVersion=$p.conditionVersion}
                    }
                }
            }
        }
        if($Planes -contains 'DirectoryRole'){
            foreach($kind in @('roleEligibilityScheduleInstances','roleAssignments')){
                $r=Invoke-MgJsonAll -Uri ('{0}/roleManagement/directory/{1}?$filter={2}' -f $GraphBase,$kind,$filter)
                if(-not $r.Ok){throw "Group-derived directory coverage incomplete: $($r.Error)"}
                foreach($record in $r.Value){
                    if($record.principalId -ine $g.GroupId -or -not $record.roleDefinitionId -or -not $record.directoryScopeId){throw 'Malformed group-derived directory assignment.'}
                    $observations+=@{Plane='DirectoryRole';Kind=$kind;GroupId=$g.GroupId;Path=$g.Path;AssignmentId=$record.id;RoleDefinitionId=$record.roleDefinitionId;Scope=$record.directoryScopeId;AppScopeId=$record.appScopeId;StartDateTime=$record.startDateTime;EndDateTime=$record.endDateTime}
                }
            }
        }
    }
    # Same inherited assignment can be returned at several scopes.
    $unique=@{};foreach($item in $observations){$key=$item | ConvertTo-Json -Compress -Depth 8;$unique[$key]=$item}
    return @{Groups=@($groups.Values | Sort-Object GroupId);Assignments=@($unique.Values | Sort-Object GroupId,Scope,RoleDefinitionId);
        Coverage='Read-only evidence of group paths, not direct grants or a complete effective-access calculation. Current transitive memberships and selected direct PIM member eligibilities only; eligible nested paths, hidden memberships without consent, activation policy, deny assignments, and condition evaluation are not covered. Group owner eligibility does not imply membership. Role-assignment records do not establish whether access is permanent.'}
}
