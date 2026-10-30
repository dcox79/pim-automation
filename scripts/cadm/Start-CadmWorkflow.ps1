#requires -Version 5.1
<#
.SYNOPSIS
Guided template builder, profile preview/apply and comparison. Default is a menu, never apply.
.DESCRIPTION
Apply requires -Apply plus typed confirmation. No Force switch. No removals or renewals.
Comparison extras cover direct resource eligibilities at the template's exact scopes only.
#>
param(
    [ValidateSet('Preview','Apply','Compare','Build','Import','Review')][string]$Action,
    [string]$TargetUser, [string]$ProfileName, [string]$ScopeToken,
    [string]$SourceUser, [switch]$Apply,
    [ValidateSet('AzureResource','Group','DirectoryRole')][string[]]$ExportPlanes=@('AzureResource'),
    [string[]]$AdditionalScopes, [switch]$IncludeManagementGroups, [switch]$IncludeGroupDerivedAccess,
    [string]$TemplateJson, [string]$OutDir,
    [ValidateRange(1,10)][int]$VerificationAttempts=3,
    [ValidateRange(0,30)][int]$VerificationDelaySeconds=5,
    [bool]$ConnectGraph=$true
)
$ErrorActionPreference='Stop'
$Interactive=$false
. (Join-Path $PSScriptRoot 'lib/CadmAccess.Core.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmProfile.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmExport.ps1')
. (Join-Path $PSScriptRoot 'lib/CadmWorkflow.ps1')
if ($Apply -and $Action -ne 'Apply') { throw 'Use -Apply only with -Action Apply.' }
if ($Action -eq 'Apply' -and -not $Apply) { throw '-Action Apply requires -Apply.' }
Initialize-AzInvoker
$tenant=Import-CadmTenant -TenantsDir (Join-Path $PSScriptRoot 'tenants')
if (-not $OutDir) { $OutDir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PIM-Automation/workflow' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not $Action) {
    Write-Host 'Example template workflow: 1 Preview, 2 Apply, 3 Compare/renewals, 4 Build, 5 Import reference user, 6 Review template, q Quit'
    switch ((Read-Host 'Choose').Trim()) {
        '1' {$Action='Preview'} '2' {$Action='Apply';$Apply=$true} '3' {$Action='Compare'} '4' {$Action='Build'} '5' {$Action='Import'} '6' {$Action='Review'} 'q' {exit 0} default {throw 'Invalid choice'}
    }
}
if ($Action -in @('Build','Import')) {
    if (-not $ProfileName) { $ProfileName=(Read-Host 'New template filename key').Trim() }
    # Resolve a selected tenant-approved scope; portable builder entries reference template-scope.
    if (-not $ScopeToken) {
        Write-Host "Configured scopes: $($tenant.ScopeTokens.Keys -join ', ')"
        $ScopeToken=(Read-Host 'Default scope token').Trim()
    }
    $null=Set-WorkflowScope $tenant $ScopeToken
    if ($TemplateJson) {
        # Convert JSON to a hashtable on both PowerShell 5.1 and 7.
        function Convert-WorkflowObject($Object) {
            if ($null -eq $Object) {return $null}
            if ($Object -is [pscustomobject]) { $h=@{}; foreach ($p in $Object.PSObject.Properties) {$h[$p.Name]=Convert-WorkflowObject $p.Value}; return $h }
            if ($Object -is [array]) { return ,@($Object | ForEach-Object {Convert-WorkflowObject $_}) }
            return $Object
        }
        $data=Convert-WorkflowObject (Get-Content -LiteralPath $TemplateJson -Raw | ConvertFrom-Json)
    } else {
        $data=@{Name=(Read-Host 'Display name');Description=(Read-Host 'Description');Rbac=@();GroupMemberships=@();PimGroupEligibilities=@();DirectoryRoleEligibilities=@();PimResourceEligibilities=@()}
        if ($Action -eq 'Import') {
            if (-not $SourceUser) {$SourceUser=(Read-Host 'Reference user exact UPN or object ID').Trim()}
            $source=Resolve-WorkflowUser $SourceUser
            $scratch=Join-Path $OutDir ([guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $scratch | Out-Null
            $exportTenant=$tenant.Clone(); $exportTenant.ProfilesDir=$scratch
            if($IncludeGroupDerivedAccess -or $ExportPlanes -contains 'Group' -or $ExportPlanes -contains 'DirectoryRole'){
                Connect-CadmExportGraph -Planes $ExportPlanes -IncludeGroupDerivedAccess:$IncludeGroupDerivedAccess
            }
            $export=Export-CadmEligibilityProfile -Source $source -Tenant $exportTenant -ProfileName 'reference' -Planes $ExportPlanes -AdditionalScopes $AdditionalScopes -IncludeManagementGroups:$IncludeManagementGroups -IncludeGroupDerivedAccess:$IncludeGroupDerivedAccess
            if(-not $export.Path){Write-Host "No direct eligibilities to import. Coverage report: $($export.CoveragePath)";exit 0}
            $import=Import-PowerShellDataFile $export.Path
            $entries=@()
            foreach($plane in @('PimResourceEligibilities','PimGroupEligibilities','DirectoryRoleEligibilities')){
                foreach($entry in @(Get-ProfileEntries $import[$plane])){$entries+=@{Plane=$plane;Entry=$entry}}
            }
            for($i=0;$i -lt $entries.Count;$i++){Write-Host "[$($i+1)] $($entries[$i].Plane) $($entries[$i].Entry | ConvertTo-Json -Compress)"}
            $selection=(Read-Host 'Select entry numbers separated by commas; no automatic all').Split(',')
            foreach($n in @($selection | Select-Object -Unique)) {
                $index=0; if(-not [int]::TryParse($n.Trim(),[ref]$index) -or $index -lt 1 -or $index -gt $entries.Count){throw 'Invalid entry selection'}
                $chosen=$entries[$index-1];$data[$chosen.Plane]+=,$chosen.Entry
            }
            $data.Export=$import.Export
            if(-not $data.Name){$data.Name=$import.Name}
            if(-not $data.Description){$data.Description=Get-CadmExportDescription -Data $data -Tenant $tenant}
            Write-Host 'Selected direct eligibilities imported; group-derived evidence remains informational. Exact scopes and finite expiries retained.'
        } else {
            $catalog=@(Invoke-AzJson -AzArgs @('role','definition','list','--scope',$tenant.ScopeTokens[$ScopeToken],'-o','json'))
            if($script:LastAzError){throw $script:LastAzError}
            $search=Read-Host 'Role name search (for example Contributor or Virtual Machine)'
            $catalog=@($catalog | Where-Object {$_.roleName -like "*$search*"} | Sort-Object roleName)
            for($i=0;$i -lt $catalog.Count;$i++){Write-Host "[$($i+1)] $($catalog[$i].roleName)"}
            $duration=(Read-Host 'Eligibility duration (ISO-8601, for example P365D)').Trim()
            foreach($n in @((Read-Host 'Select role numbers separated by commas').Split(',') | Select-Object -Unique)) {
                $index=0;if(-not [int]::TryParse($n.Trim(),[ref]$index) -or $index -lt 1 -or $index -gt $catalog.Count){throw 'Invalid role selection'}
                $data.PimResourceEligibilities+=@{RoleDefinitionId=(Get-RoleDefGuid $catalog[$index-1].id);Scope='template-scope';Duration=$duration}
            }
        }
        if(-not ($data.PimResourceEligibilities.Count+$data.PimGroupEligibilities.Count+$data.DirectoryRoleEligibilities.Count)){throw 'Select at least one eligibility'}
        $data.Metadata=@{SchemaVersion='1';Version='1.0.0';Owner=(Read-Host 'Template owner');Purpose=(Read-Host 'Business purpose');ReviewDate=(Read-Host 'Next review date (yyyy-MM-dd)');Status='Draft';DefaultScopeToken=$ScopeToken}
        Write-Host ($data | ConvertTo-Json -Depth 15)
        if((Read-Host 'Type REVIEWED to mark this template reviewed, or Enter to keep Draft') -ceq 'REVIEWED') {
            $data.Metadata.Reviewer=(Read-Host 'Reviewer identity').Trim(); $data.Metadata.Status='Reviewed'
            Assert-WorkflowMetadata $data -ForApply
        }
    }
    $saved=Save-WorkflowTemplate -Data $data -Key $ProfileName -Tenant $tenant
    Write-Host "Saved $saved. No access granted."
    exit 0
}
$profiles=@(Get-CadmProfiles $tenant.ProfilesDir)
if(-not $ProfileName) {
    for($i=0;$i -lt $profiles.Count;$i++){Write-Host "[$($i+1)] $($profiles[$i].Key) - $($profiles[$i].Description)"}
    $choice=0; if(-not [int]::TryParse((Read-Host 'Template number'),[ref]$choice) -or $choice -lt 1 -or $choice -gt $profiles.Count){throw 'Invalid template selection'}
    $ProfileName=$profiles[$choice-1].Key
}
$profile=@($profiles | Where-Object Key -eq $ProfileName)
if($profile.Count -ne 1){throw 'Template not uniquely found'}; $profile=$profile[0]
if($Action -eq 'Review') {
    Write-Host (Get-Content -LiteralPath $profile.Path -Raw)
    $m=$profile.Data.Metadata
    $m.Owner=(Read-Host 'Template owner').Trim();$m.Purpose=(Read-Host 'Business purpose').Trim()
    $m.Version=(Read-Host 'New semantic version (must differ from current)').Trim()
    $old=Import-PowerShellDataFile $profile.Path
    if($m.Version -notmatch '^\d+\.\d+\.\d+$' -or [version]$m.Version -le [version]$old.Metadata.Version){throw 'Increment the version for a changed review.'}
    $m.ReviewDate=(Read-Host 'Next review date (yyyy-MM-dd)').Trim();$m.Reviewer=(Read-Host 'Reviewer identity').Trim()
    $m.Status='Reviewed';Assert-WorkflowMetadata $profile.Data -ForApply
    if((Read-Host 'Type REVIEWED to record this operator review; this does not grant access') -cne 'REVIEWED'){exit 0}
    $snapshot=Backup-CadmProfileFiles -Tenant $tenant -ProfilePaths @($profile.Path) -Reason 'Before template review edit'
    $backup=$snapshot.Path
    $temp=Join-Path $tenant.ProfilesDir (".$([guid]::NewGuid()).psd1")
    try {
        [IO.File]::WriteAllText($temp,(ConvertTo-CadmPsdLiteral $profile.Data),[Text.UTF8Encoding]::new($true))
        $null=Import-PowerShellDataFile $temp
        [IO.File]::Replace($temp,$profile.Path,[NullString]::Value)
    } finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp}}
    Write-Host "Review recorded. Previous version saved to $backup. No access granted.";exit 0
}
Assert-WorkflowMetadata $profile.Data -ForApply:($Action -eq 'Apply')
if(@($profile.Data.PimResourceEligibilities | Where-Object Scope -eq 'template-scope').Count){
    if(-not $ScopeToken){$ScopeToken=$profile.Data.Metadata.DefaultScopeToken}
    $null=Set-WorkflowScope $tenant $ScopeToken
}
elseif($ScopeToken){throw 'Scope override requires a template using template-scope; fixed-scope templates cannot be retargeted.'}
Assert-ProfileSafe -Profile $profile -Tenant $tenant
$profileBackup=Backup-CadmProfileFiles -Tenant $tenant -ProfilePaths @($profile.Path) -Reason 'Workflow preview/apply/compare'
Write-Host "Local profile backup: $($profileBackup.Path)"
if(-not $TargetUser){$TargetUser=(Read-Host 'Target exact UPN or object ID').Trim()}
$target=Resolve-WorkflowUser $TargetUser
$acct=Invoke-AzJson -AzArgs @('account','show','-o','json')
$usesGroups=@(Get-ProfileEntries $profile.Data.PimGroupEligibilities).Count -or @(Get-ProfileEntries $profile.Data.GroupMemberships).Count
$usesDirectory=@(Get-ProfileEntries $profile.Data.DirectoryRoleEligibilities).Count
if($usesDirectory){$extra=if($Action -eq 'Apply'){$MgDirWriteScopeList}else{$MgDirReadScopeList};$MgScopeList=@($MgScopeList+$extra | Select-Object -Unique);$MgScopes=$MgScopeList -join ','}
if($usesGroups -or $usesDirectory){Connect-GraphIfNeeded -ProbePrincipalId $target.id}
$subs=@() # Exact profile scopes are verified individually; no subscription inventory is needed.
$rows=@(Get-WorkflowPlan -Profile $profile -Target $target -Tenant $tenant -Subs $subs)
if(-not $rows.Count){throw 'Template resolved to an empty plan; review the template.'}
$runId=[guid]::NewGuid().ToString();$runDir=Join-Path $OutDir $runId;New-Item -ItemType Directory -Path $runDir | Out-Null
$hash=(Get-WorkflowFileHash $profile.Path)
$tenantHash=(Get-WorkflowFileHash $tenant.Path)
$review=[ordered]@{RunId=$runId;State='Preview';TimestampUtc=[datetimeoffset]::UtcNow.ToString('o');TenantId=$tenant.TenantId;Actor=$acct.user.name;Target=$target;Template=$ProfileName;TemplateHash=$hash;TenantHash=$tenantHash;BackupPath=$profileBackup.Path;Metadata=$profile.Data.Metadata;Plan=$rows;Coverage='Expected profile entries. Extra/renewal inventory: direct Azure-resource eligibilities at exact template scopes only; not all effective access.'}
Write-WorkflowJson $review (Join-Path $runDir 'review.json')
Write-Host "Target: $($target.displayName) <$($target.userPrincipalName)> [$($target.id)]"
Write-Host "Template: $ProfileName v$($profile.Data.Metadata.Version) / $($profile.Data.Metadata.Status)"
$rows | Select-Object Plane,Action,Item,Scope,@{n='EligibilityTerm';e={if($_.ScheduleInfo){$_.ScheduleInfo.expiration | ConvertTo-Json -Compress}elseif($_.Plane -in @('RBAC','GROUP')){'Standing access'}else{'Existing eligibility retained; expiry unchanged'}}} | Format-Table -Wrap | Out-Host
Show-CadmActivationChecks -Rows $rows
Write-Host 'Management-group permissions extend to descendant scopes. Group/directory activation policy and Conditional Access behavior are not checked.'
if($Action -eq 'Compare') {
    $inventory=@(Get-WorkflowResourceReport -Rows $rows -Target $target)
    Write-WorkflowJson @{RunId=$runId;ExpectedPlan=$rows;ResourceInventory=$inventory;Coverage=$review.Coverage} (Join-Path $runDir 'comparison.json')
    $inventory | Format-Table RoleDefinitionId,Classification,Status,EndDateTime -AutoSize | Out-Host
    Write-Host "Comparison saved to $runDir. Extra access is reported only; nothing removed or renewed.";exit 0
}
if($Action -eq 'Preview'){Write-Host "Preview saved to $runDir. Nothing changed.";if(@($rows | Where-Object {$_.Action -notin @('CREATE','SKIP-EXISTS')}).Count){exit 2};exit 0}
# Confirmation and any subsequent refusal are recorded before returning.
try {
    if(-not $Apply -and $PSBoundParameters.ContainsKey('Action')){throw 'Explicit -Action Apply also requires -Apply.'}
    if(@($rows | Where-Object {$_.Action -notin @('CREATE','SKIP-EXISTS')}).Count){throw 'Plan has blocked or unknown entries; refusing apply.'}
    $phrase="APPLY $($target.userPrincipalName)"
    if((Read-Host "Type $phrase to confirm these exact assignments") -cne $phrase){
        $review.State='Cancelled';Write-WorkflowJson $review (Join-Path $runDir 'review.json');exit 0
    }
    if((Get-WorkflowFileHash $profile.Path) -ne $hash -or (Get-WorkflowFileHash $tenant.Path) -ne $tenantHash){throw 'Configuration changed since review; preview again.'}
    Assert-CadmAzContext
    $reviewedUpn=$target.userPrincipalName
    $target=Resolve-WorkflowUser $target.id
    if($target.userPrincipalName -cne $reviewedUpn){throw 'Account changed since review; preview again.'}
    $fresh=@(Get-WorkflowPlan -Profile $profile -Target $target -Tenant $tenant -Subs $subs)
    if((Get-WorkflowFingerprint $fresh) -cne (Get-WorkflowFingerprint $rows)){throw 'Access or policy changed since review; preview again.'}
}catch{
    $review.State='Refused';$review.Error=$_.Exception.Message
    Write-WorkflowJson $review (Join-Path $runDir 'review.json')
    throw
}
$review.State='Approved';Write-WorkflowJson $review (Join-Path $runDir 'review.json')
$outcome=Invoke-CadmAuditedProfileApply -Rows $fresh -Target $target -Justification "$($tenant.JustificationPrefix): $($profile.Name) v$($profile.Data.Metadata.Version); run $runId" -DefaultDuration $tenant.DefaultEligibilityDuration -RunDirectory $runDir -Context $review -VerificationAttempts $VerificationAttempts -VerificationDelaySeconds $VerificationDelaySeconds
$review.State=$outcome.State;Write-WorkflowJson $review (Join-Path $runDir 'review.json')
$outcome.Verification | Format-Table Plane,Role,Status,Scope -Wrap | Out-Host
Write-Host "Outcome: $($outcome.State). Evidence: $runDir"
if($outcome.State -ne 'Verified'){exit 1}
