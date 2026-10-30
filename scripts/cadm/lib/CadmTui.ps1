#requires -Version 5.1
# Dependency-free, line-oriented terminal UI. Cloud operations remain in existing entry points.
function Format-CadmTuiText {
    param($Value)
    return ([string]$Value -replace '[\x00-\x1f\x7f]', ' ')
}
function Read-CadmTuiChoice {
    param([string]$Title,[string[]]$Items,[string]$BackLabel='Back',[string[]]$Descriptions=@())
    while($true){
        Write-Host '';Write-Host $Title
        for($i=0;$i -lt $Items.Count;$i++){
            Write-Host ("  [{0}] {1}" -f ($i+1),(Format-CadmTuiText $Items[$i]))
            if($i -lt $Descriptions.Count){Write-Host ("      {0}" -f (Format-CadmTuiText $Descriptions[$i]))}
        }
        Write-Host "  [b] $BackLabel"
        $answer=Read-Host 'Choose a number (Enter or b to go back)'
        if($null -eq $answer -or $answer.Trim() -in @('','b','q')){return -1}
        $n=0
        if([int]::TryParse($answer.Trim(),[ref]$n) -and $n -ge 1 -and $n -le $Items.Count){return ($n-1)}
        Write-Host 'Please enter one of the listed numbers, or b.'
    }
}
function Get-CadmTuiContext {
    Initialize-AzInvoker
    $tenant=Import-CadmTenant -TenantsDir (Join-Path $script:TuiRoot 'tenants')
    Write-Host ("Tenant: {0} [{1}]" -f (Format-CadmTuiText $tenant.Name),$tenant.TenantId)
    return $tenant
}
function Select-CadmTuiProfile {
    param($Tenant)
    $profiles=@(Get-CadmProfiles -ProfilesDir $Tenant.ProfilesDir)
    if(-not $profiles.Count){Write-Host 'No access profiles found. Use option 3 to export an existing user''s PIM eligibility.';return $null}
    $labels=@($profiles | ForEach-Object {"$($_.Name) [$($_.Key)] - $($_.Description)"})
    $index=Read-CadmTuiChoice 'Choose a profile' $labels
    if($index -lt 0){return $null}
    return $profiles[$index]
}
function Select-CadmTuiUser {
    param([string]$Purpose)
    while($true){
        Write-Host '';Write-Host "$Purpose - search by name, surname, email address, or object ID."
        $search=Read-Host 'Search (Enter or b to go back)'
        if($null -eq $search -or $search.Trim() -in @('','b')){return $null}
        $search=$search.Trim()
        if($search.Length -lt 2){Write-Host 'Enter at least two characters.';continue}
        $guid=[guid]::Empty
        if([guid]::TryParse($search,[ref]$guid) -or $search.Contains('@')){
            # Exact identities must not fall back to a prefix match.
            $user=Resolve-CadmUser -Ref $search
            if(($search.Contains('@') -and $user.userPrincipalName -ine $search) -or
               (-not $search.Contains('@') -and $user.id -ine $search)){throw 'Exact account lookup did not match.'}
            $users=@($user)
        }else{
            $literal=$search.Replace("'","''")
            $filter=[uri]::EscapeDataString("startswith(displayName,'$literal') or startswith(surname,'$literal') or startswith(userPrincipalName,'$literal')")
            $users=@(Invoke-CadmRestAll -Url ('{0}/users?$filter={1}&$select=id,displayName,userPrincipalName,accountEnabled&$top=50' -f $GraphBase,$filter))
        }
        $users=@($users | Sort-Object userPrincipalName)
        if(-not $users.Count){Write-Host 'No accounts matched. Try a surname or exact email address.';continue}
        if($users.Count -gt 50){Write-Host "Found $($users.Count) accounts. Use a more specific search.";continue}
        $index=Read-CadmTuiChoice 'Select the exact account' @($users | ForEach-Object {
            "$($_.displayName) <$($_.userPrincipalName)> [$($_.id)]$(if(-not $_.accountEnabled){' (disabled or unreadable)'})"
        }) 'Search again'
        if($index -lt 0){continue}
        $chosen=$users[$index]
        $id=[guid]::Empty
        if(-not [guid]::TryParse([string]$chosen.id,[ref]$id) -or $id -eq [guid]::Empty -or -not $chosen.userPrincipalName){throw 'Selected account has incomplete identity data.'}
        if($chosen.accountEnabled -ne $true){Write-Host 'That account is disabled or its status is unreadable. Choose another account.';continue}
        return $chosen
    }
}
function Select-CadmTuiScope {
    param($Tenant)
    $keys=@($Tenant.ScopeTokens.Keys | Where-Object {$_ -ne 'template-scope'} | Sort-Object)
    if(-not $keys.Count){throw 'No tenant scope tokens are configured.'}
    $index=Read-CadmTuiChoice 'Choose a configured scope' @($keys | ForEach-Object {"$_ - $($Tenant.ScopeTokens[$_])"})
    if($index -lt 0){return $null}
    return $keys[$index]
}
function Invoke-CadmTuiCommand {
    param([string]$ScriptName,[hashtable]$Arguments)
    $path=Join-Path $script:TuiRoot $ScriptName
    if(-not (Test-Path -LiteralPath $path)){throw "Command is missing: $ScriptName"}
    # Call scripts with structured arguments; never evaluate generated command text.
    $global:LASTEXITCODE=0
    & $path @Arguments | Out-Host
    $code=$LASTEXITCODE
    if($code -ne 0){Write-Host "Operation did not complete successfully (exit $code). Read the result above; the menu remains available."}
    return $code
}
function Invoke-CadmTuiProfile {
    param([switch]$Apply)
    $tenant=Get-CadmTuiContext
    $profile=Select-CadmTuiProfile $tenant
    if(-not $profile){return}
    $user=Select-CadmTuiUser 'Target account'
    if(-not $user){return}
    $portable=@(Get-ProfileEntries $profile.Data.PimResourceEligibilities | Where-Object Scope -eq 'template-scope').Count -gt 0
    $parameters=@{ProfileName=$profile.Key;TargetUser=$user.id;ConnectGraph=$script:TuiConnectGraph;OutDir=$script:TuiOutDir}
    if($portable){
        $scope=Select-CadmTuiScope $tenant
        if(-not $scope){return}
        $scriptName='Start-CadmWorkflow.ps1';$parameters.Action='Preview';$parameters.ScopeToken=$scope
    }else{$scriptName='Invoke-CadmAccess.ps1';$parameters.Mode='profile';$parameters.Apply=$false}
    Write-Host ("Previewing {0} for {1}. No access will be changed." -f (Format-CadmTuiText $profile.Name),(Format-CadmTuiText $user.userPrincipalName))
    $code=Invoke-CadmTuiCommand -ScriptName $scriptName -Arguments $parameters
    if(-not $Apply -or $code -ne 0){return}
    $choice=Read-CadmTuiChoice 'Preview completed. Continue to the apply confirmation?' @('Continue - the plan is checked again before any changes')
    if($choice -lt 0){Write-Host 'Apply cancelled. Preview only.';return}
    $parameters.Apply=$true
    if($portable){$parameters.Action='Apply'}
    else{$parameters.ConfirmTarget=$true}
    # No Force switch. The backend presents the current plan and requires the exact account phrase.
    $null=Invoke-CadmTuiCommand -ScriptName $scriptName -Arguments $parameters
}
function Invoke-CadmTuiExport {
    Write-Host 'This saves a new local access profile from existing eligibility. Source expiry dates are preserved; nobody receives access.'
    $tenant=Get-CadmTuiContext
    $source=Select-CadmTuiUser 'Account to export'
    if(-not $source){return}
    $plane=Read-CadmTuiChoice 'What should the new profile contain?' @(
        'Azure roles - for example Owner or Contributor on subscriptions or management groups (Azure CLI)',
        'Group eligibility - permission to activate group membership or ownership (Graph access required)',
        'Directory roles - for example Global Administrator in Microsoft Entra (Graph access required)',
        'All of the above (Graph access required)')
    if($plane -lt 0){return}
    $planes=switch($plane){0 {@('AzureResource')} 1 {@('Group')} 2 {@('DirectoryRole')} 3 {@('AzureResource','Group','DirectoryRole')}}
    $parameters=@{Mode='export';SourceUser=$source.id;ExportPlanes=@($planes);ConnectGraph=$script:TuiConnectGraph}
    if($planes -contains 'AzureResource'){
        $coverage=Read-CadmTuiChoice 'Azure discovery coverage' @('Search subscriptions visible to your signed-in account','Also search visible management groups (broader coverage)','Search subscriptions plus one scope saved in your tenant settings')
        if($coverage -lt 0){return}
        if($coverage -eq 1){$parameters.IncludeManagementGroups=$true}
        if($coverage -eq 2){$scope=Select-CadmTuiScope $tenant;if(-not $scope){return};$parameters.AdditionalScopes=@($scope)}
    }
    $parameters.IncludeGroupDerivedAccess=$script:TuiGroupCoverage
    while($true){
        $key=Read-Host 'New profile name (letters, numbers, hyphens; Enter to cancel)'
        if([string]::IsNullOrWhiteSpace($key)){return}
        $key=$key.Trim()
        if($key -notmatch '^[a-z0-9][a-z0-9-]{0,63}$' -or $key -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])$'){Write-Host 'Use a non-reserved name of 1-64 letters, numbers, or hyphens.';continue}
        if((Test-Path -LiteralPath (Join-Path $tenant.ProfilesDir "$key.psd1")) -or (Test-Path -LiteralPath (Join-Path $tenant.ProfilesDir "$key.coverage.json"))){Write-Host 'That name already exists. Choose a new name.';continue}
        $parameters.ProfileName=$key;break
    }
    Write-Host 'Source expiry dates will be preserved. Export creates a local template, not access.'
    $null=Invoke-CadmTuiCommand -ScriptName 'Invoke-CadmAccess.ps1' -Arguments $parameters
}
function Select-CadmTuiLocalTenant {
    $tenants=@(Get-ChildItem -LiteralPath (Join-Path $script:TuiRoot 'tenants') -Directory | Where-Object {Test-Path -LiteralPath (Join-Path $_.FullName 'tenant.psd1')} | Sort-Object Name)
    $index=Read-CadmTuiChoice 'Choose a local tenant (no Azure connection needed)' @($tenants | ForEach-Object {$_.Name})
    if($index -lt 0){return $null}
    return $tenants[$index]
}
function Show-CadmTuiProfiles {
    $folder=Select-CadmTuiLocalTenant
    if(-not $folder){return}
    $tenant=@{ProfilesDir=(Join-Path $folder.FullName 'profiles')}
    $profile=Select-CadmTuiProfile $tenant
    if(-not $profile){return}
    Write-Host ("Profile: {0}" -f (Format-CadmTuiText $profile.Name))
    Write-Host ("File: {0}" -f $profile.Path)
    foreach($plane in @('PimResourceEligibilities','PimGroupEligibilities','DirectoryRoleEligibilities','Rbac','GroupMemberships')){
        $entries=@(Get-ProfileEntries $profile.Data[$plane])
        if($entries.Count){
            Write-Host "$plane ($($entries.Count))"
            foreach($entry in $entries){Write-Host (Format-CadmTuiText ($entry | ConvertTo-Json -Depth 8 -Compress))}
        }
    }
    Write-Host 'Browsing a profile does not grant or activate access.'
}
function Show-CadmTuiReports {
    if(-not (Test-Path -LiteralPath $script:TuiOutDir)){Write-Host 'No reports from this menu yet. Run a preview first.';return}
    $files=@(Get-ChildItem -LiteralPath $script:TuiOutDir -File -Recurse | Where-Object Name -in @('review.json','outcome.json','comparison.json') | Sort-Object LastWriteTime -Descending | Select-Object -First 15)
    if(-not $files.Count){Write-Host 'No reports from this menu yet.';return}
    $index=Read-CadmTuiChoice 'Recent reports from this menu' @($files | ForEach-Object {"$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) - $($_.Name) - $($_.Directory.Name)"})
    if($index -lt 0){return}
    $report=Get-Content -LiteralPath $files[$index].FullName -Raw | ConvertFrom-Json
    Write-Host $files[$index].FullName
    $context=if($report.Context){$report.Context}else{$report}
    Write-Host ("State: {0}  Template: {1}  Target: {2}" -f (Format-CadmTuiText $report.State),(Format-CadmTuiText $context.Template),(Format-CadmTuiText $context.Target.userPrincipalName))
    $rows=if($report.Verification){$report.Verification}elseif($report.Plan){$report.Plan}else{$report.ExpectedPlan}
    $rows | ForEach-Object {
        [pscustomobject]@{
            Type=Format-CadmTuiText $_.Plane
            Role=Format-CadmTuiText $(if($_.Role){$_.Role}else{$_.Item})
            Result=Format-CadmTuiText $(if($_.Status){$_.Status}else{$_.Action})
            Scope=Format-CadmTuiText $_.Scope
            Detail=Format-CadmTuiText $_.Detail
        }
    } | Format-Table -Wrap | Out-Host
}
function Start-CadmTuiLoop {
    param([string]$Root,[string]$OutDir,[bool]$ConnectGraph=$false)
    $script:TuiRoot=$Root;$script:TuiOutDir=$OutDir;$script:TuiConnectGraph=$ConnectGraph;$script:TuiGroupCoverage=$false
    while($true){
        Write-Host '';Write-Host 'PIM ACCESS'
        Write-Host "Graph sign-in: $(if($script:TuiConnectGraph){'allowed when needed'}else{'off - existing sessions only'})"
        Write-Host 'A profile is a saved recipe for access. New here? Start with option 8 to configure your tenant.'
        $choice=Read-CadmTuiChoice 'Choose a task' @(
            'Preview access for a user',
            'Assign access to a user',
            'Create a profile from an existing user',
            'Read a saved profile',
            'Save a local backup',
            'Read previous results',
            'Change connection and export settings',
            'Set up a tenant (first-time setup)') 'Quit' -Descriptions @(
            'Choose a profile and account. Read Azure and show proposed changes and blockers; save a local report. Grants nothing.',
            'Preview first, then type the exact account confirmation. Can grant the profile permissions; PIM eligibility still needs activation.',
            'Read a user''s PIM eligibility and save a NEW reusable profile, keeping expiry dates. Does not copy active sessions or grant access.',
            'Open a local profile to see the permissions and scopes it contains. No Azure connection; does not check the user''s current access.',
            'Copy local tenant settings and profiles into a dated backup folder. No Azure connection; backup stays on this computer.',
            'View saved previews and apply verification results from this menu. These are past results, not a fresh Azure check.',
            'Choose whether Graph sign-in may open and whether exports include evidence of access through groups. Grants no permissions.',
            'Create local settings for an Azure directory and optionally a Reader starter profile. No sign-in, Azure resources or access grants.')
        if($choice -lt 0){Write-Host 'Menu closed.';return}
        try{
            switch($choice){
                0 {Invoke-CadmTuiProfile}
                1 {Invoke-CadmTuiProfile -Apply}
                2 {Invoke-CadmTuiExport}
                3 {Show-CadmTuiProfiles}
                4 {$folder=Select-CadmTuiLocalTenant;if($folder){$null=Invoke-CadmTuiCommand -ScriptName 'Backup-CadmProfiles.ps1' -Arguments @{TenantName=$folder.Name}}}
                5 {Show-CadmTuiReports}
                7 {. (Join-Path $script:TuiRoot 'lib/CadmSetup.ps1');Invoke-CadmTuiSetup}
                6 {
                    $option=Read-CadmTuiChoice 'Options - no connection or consent is started here' @(
                        'Keep automatic Graph sign-in OFF (use existing sessions only)',
                        'Allow Graph sign-in when a selected operation needs it',
                        'Export direct eligibility only',
                        'Include group-derived evidence in exports (requires Graph reads)')
                    switch($option){0 {$script:TuiConnectGraph=$false} 1 {$script:TuiConnectGraph=$true} 2 {$script:TuiGroupCoverage=$false} 3 {$script:TuiGroupCoverage=$true}}
                    Write-Host "Group-derived export evidence: $($script:TuiGroupCoverage)"
                }
            }
        }catch{
            Write-Host ("Operation stopped: {0}" -f (Format-CadmTuiText $_.Exception.Message))
            Write-Host 'Nothing will be retried automatically. For missing tenant configuration use option 8. For Azure sign-in problems, use az login in your terminal.'
        }
    }
}
