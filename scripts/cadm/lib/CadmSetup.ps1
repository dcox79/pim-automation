#requires -Version 5.1
# Local onboarding only. Never connects to Azure or submits grants.
. (Join-Path $PSScriptRoot 'CadmExport.ps1')

function Assert-CadmTenantSetup {
    param([string]$TenantsDir,[string]$Key,[string]$Name,[string]$TenantId,[string]$Scope,
          [int]$DefaultDays=365)
    if($Key -cnotmatch '^[a-z0-9][a-z0-9-]{0,63}$' -or
       $Key -match '^(example|con|prn|aux|nul|com[0-9]|lpt[0-9])$'){
        throw 'Choose a new tenant folder name using lowercase letters, numbers and hyphens; reserved names and example are not allowed.'
    }
    if([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 120 -or $Name -match '[\x00-\x1f\x7f]'){
        throw 'Enter a tenant display name of 1-120 printable characters.'
    }
    $id=[guid]::Empty
    if(-not [guid]::TryParse($TenantId,[ref]$id) -or $id -eq [guid]::Empty){throw 'Enter a real, non-zero tenant ID.'}
    if($DefaultDays -lt 1 -or $DefaultDays -gt 3650){throw 'The default eligibility term must be 1-3650 days.'}
    $null=Resolve-CadmScope -Scope $Scope -Tenant @{}
    if(-not (Test-Path -LiteralPath $TenantsDir -PathType Container)){throw 'The tenants directory is missing.'}
    # OneDrive marks ordinary synced directories ReparsePoint even without a link target.
    # Refuse actual path-redirection links; the attribute alone is not a symlink test.
    $folderInfo=Get-Item -LiteralPath $TenantsDir
    if($folderInfo.LinkType -or @($folderInfo.Target | Where-Object {$_}).Count){
        throw 'Use a regular tenants directory, not a symbolic link or junction.'
    }
    if(Test-Path -LiteralPath (Join-Path $TenantsDir $Key)){throw 'That tenant folder already exists. Existing configuration will not be replaced.'}
    foreach($folder in @(Get-ChildItem -LiteralPath $TenantsDir -Directory)){
        $file=Join-Path $folder.FullName 'tenant.psd1'
        if(Test-Path -LiteralPath $file){
            $existing=Import-PowerShellDataFile -LiteralPath $file
            if([string]$existing.TenantId -ieq $id.ToString()){
                throw "This tenant ID is already configured in '$($folder.Name)'. Use its existing profiles."
            }
        }
    }
}
function Write-CadmSetupFile {
    param([string]$Path,[string]$Text)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{
        $writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($true))
        try{$writer.Write($Text)}finally{$writer.Dispose()}
    }finally{$stream.Dispose()}
}
function New-CadmTenantConfiguration {
    param([string]$TenantsDir,[string]$Key,[string]$Name,[string]$TenantId,[string]$Scope,
          [int]$DefaultDays=365,[switch]$ReaderProfile)
    Assert-CadmTenantSetup -TenantsDir $TenantsDir -Key $Key -Name $Name -TenantId $TenantId -Scope $Scope -DefaultDays $DefaultDays
    $id=([guid]$TenantId).ToString()
    $directory=Join-Path $TenantsDir $Key
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    try{
        $profiles=Join-Path $directory 'profiles'
        $null=New-Item -ItemType Directory -Path $profiles -ErrorAction Stop
        $data=[ordered]@{
            Name=$Name;TenantId=$id;RootManagementGroupId=$id
            ScopeTokens=@{'default-scope'=$Scope}
            JustificationPrefix='CADM provisioning (profile)'
            DefaultEligibilityDuration="P$($DefaultDays)D"
            ActivationRequirements=@{}
        }
        $profilePath=$null
        if($ReaderProfile){
            $reader=[ordered]@{
                Name="$Name Reader";Description="Standing Reader at $Scope. Read access without PIM activation; no access is granted until this profile is applied."
                Rbac=@(@{Role='Reader';Scope='default-scope'})
                PimResourceEligibilities=@();GroupMemberships=@();PimGroupEligibilities=@();DirectoryRoleEligibilities=@()
            }
            $profilePath=Join-Path $profiles 'reader-only.psd1'
            Write-CadmSetupFile $profilePath (ConvertTo-CadmPsdLiteral $reader)
            $null=Import-PowerShellDataFile -LiteralPath $profilePath
        }
        # Publish tenant.psd1 last: failed setup is not discoverable as a complete binding.
        $pending=Join-Path $directory 'tenant.pending.psd1'
        Write-CadmSetupFile $pending ("# Created locally. Tenant and scope ownership are checked during cloud operations."+[Environment]::NewLine+(ConvertTo-CadmPsdLiteral $data))
        $null=Import-PowerShellDataFile -LiteralPath $pending
        $path=Join-Path $directory 'tenant.psd1'
        [IO.File]::Move($pending,$path)
        return [pscustomobject]@{Path=$path;ProfilesDir=$profiles;ProfilePath=$profilePath;TenantId=$id}
    }catch{
        throw "Setup did not finish. Inspect the new local folder '$directory' before trying again. $($_.Exception.Message)"
    }
}
function Read-CadmSetupValue {
    param([string]$Prompt,[string]$Pattern='.+')
    while($true){
        $value=Read-Host "$Prompt (Enter or b to cancel)"
        if([string]::IsNullOrWhiteSpace($value) -or $value.Trim() -eq 'b'){return $null}
        $value=$value.Trim()
        if($value -cmatch $Pattern -and $value -notmatch '[\x00-\x1f\x7f]'){return $value}
        Write-Host 'That value is not in the expected format. Please try again.'
    }
}
function Invoke-CadmTuiSetup {
    Write-Host ''
    Write-Host 'SET UP A TENANT - local files only; no Azure sign-in is needed.'
    Write-Host 'A tenant is your Azure directory. Its configuration tells this tool which directory and scopes to use.'
    Write-Host 'An access profile is a reusable list of permissions. Saving one does not give anyone access.'
    $key=Read-CadmSetupValue 'New tenant folder name, for example odyssey' '^[a-z0-9][a-z0-9-]{0,63}$'
    if(-not $key){return}
    $name=Read-CadmSetupValue 'Tenant display name, for example Odyssey Group' '^.{1,120}$'
    if(-not $name){return}
    Write-Host 'Find the tenant ID in Azure Portal > Microsoft Entra ID > Overview > Tenant ID.'
    $tid=Read-CadmSetupValue 'Tenant ID (directory GUID)' '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
    if(-not $tid){return}
    $kind=Read-CadmTuiChoice 'Where should the first configured scope be?' @(
        'One subscription - enter its subscription ID',
        'One management group - enter its ID, not its display name',
        'Tenant root management group - includes all descendant subscriptions')
    if($kind -lt 0){return}
    if($kind -eq 0){
        $scopeId=Read-CadmSetupValue 'Subscription ID (Azure Portal > Subscriptions)' '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'
        if(-not $scopeId){return}
        if([guid]$scopeId -eq [guid]::Empty){throw 'A zero subscription ID cannot be used.'}
        $scope="/subscriptions/$scopeId"
    }elseif($kind -eq 1){
        $scopeId=Read-CadmSetupValue 'Management group ID (Azure Portal > Management groups)' '^[a-zA-Z0-9_.()-]{1,90}$'
        if(-not $scopeId){return}
        $scope="/providers/Microsoft.Management/managementGroups/$scopeId"
    }else{$scope="/providers/Microsoft.Management/managementGroups/$tid"}
    Write-Host 'Default eligibility term is used only when a profile needs a fallback duration.'
    Write-Host 'Exported finite expiry dates are preserved. Azure policies still control what can be assigned.'
    while($true){
        $term=Read-Host 'Default eligibility term in days (Enter = 365; b = cancel)'
        if($term -eq 'b'){return}
        if([string]::IsNullOrWhiteSpace($term)){$term='365'}
        $days=0
        if([int]::TryParse($term,[ref]$days) -and $days -ge 1 -and $days -le 3650){break}
        Write-Host 'Enter a whole number from 1 to 3650.'
    }
    $starter=Read-CadmTuiChoice 'How should you create your first access profile?' @(
        'Export PIM eligibility later - create configuration and an empty profiles folder now',
        'Create a Reader starter template - standing read access at the selected scope, without PIM activation')
    if($starter -lt 0){return}
    $parameters=@{TenantsDir=(Join-Path $script:TuiRoot 'tenants');Key=$key;Name=$name;TenantId=$tid;Scope=$scope;DefaultDays=$days;ReaderProfile=($starter -eq 1)}
    Assert-CadmTenantSetup -TenantsDir $parameters.TenantsDir -Key $key -Name $name -TenantId $tid -Scope $scope -DefaultDays $days
    Write-Host ''
    Write-Host "Save tenant: $name [$tid]"
    Write-Host "Local folder: $(Join-Path $parameters.TenantsDir $key)"
    Write-Host "Configured scope: $scope"
    Write-Host "Fallback eligibility term: $days days"
    Write-Host "First profile: $(if($starter -eq 1){'Reader (standing access if later applied)'}else{'None yet - export existing PIM eligibility using option 3'})"
    Write-Host 'Activation settings: use existing Azure policy; no additional local MFA, approval or duration requirements.'
    Write-Host 'Tenant and scope have not been checked in Azure. They will be checked by subsequent cloud operations.'
    $confirm=Read-CadmTuiChoice 'Save these local files?' @('Save tenant configuration')
    if($confirm -lt 0){Write-Host 'Setup cancelled. No files created.';return}
    $result=New-CadmTenantConfiguration @parameters
    Write-Host "Created: $($result.Path)"
    if($result.ProfilePath){Write-Host "Created: $($result.ProfilePath)"}
    Write-Host "Next, sign in from your terminal: az login --tenant $($result.TenantId)"
    Write-Host $(if($starter -eq 1){'Then use option 1 to preview the Reader profile for a user.'}else{'Then use option 3 to save an existing user''s PIM eligibility as your first access profile.'})
}

