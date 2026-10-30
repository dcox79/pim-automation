#requires -Version 5.1
# Read-only Azure-resource activation policy inspection. Never changes Azure policy.
function Get-CadmActivationRequirements {
    param($Tenant)
    $configured=Get-CadmField $Tenant 'ActivationRequirements'
    $requirements=@{RequireMfa=$false;RequireApproval=$false;MaximumActivationDuration=$null}
    if($null -ne $configured){
        if($configured -isnot [System.Collections.IDictionary]){throw 'ActivationRequirements must be a data map.'}
        foreach($key in $configured.Keys){
            if($key -notin @('RequireMfa','RequireApproval','MaximumActivationDuration')){throw "Unknown activation requirement: $key"}
            $requirements[$key]=$configured[$key]
        }
    }
    foreach($key in @('RequireMfa','RequireApproval')){
        if($requirements[$key] -isnot [bool]){throw "$key must be a Boolean, not text."}
    }
    if($null -ne $requirements.MaximumActivationDuration){
        $maximum=ConvertTo-CadmTimeSpan $requirements.MaximumActivationDuration
        if(-not $maximum -or $maximum -le [timespan]::Zero){throw 'MaximumActivationDuration must be a positive ISO-8601 duration.'}
    }
    return $requirements
}
function Get-CadmAzureActivationCheck {
    param([string]$Scope,[string]$RoleDefinitionId,$Requirements)
    $result=[ordered]@{
        Status='Unknown';Mode='ReportOnly';Scope=$Scope;RoleDefinitionId=$RoleDefinitionId
        CheckedUtc=[datetimeoffset]::UtcNow.ToString('o');PolicyId=$null
        MfaRequired=$null;ApprovalRequired=$null;ApproversConfigured=$null
        MaximumActivationDuration=$null;ExpirationRequired=$null
        AuthenticationContextEnabled=$null;PolicyFingerprint=$null;Requirements=$Requirements;Reasons=@()
    }
    try{
        $Requirements=Get-CadmActivationRequirements @{ActivationRequirements=$Requirements}
        $result.Requirements=$Requirements
        $enforce=$Requirements.RequireMfa -or $Requirements.RequireApproval -or $null -ne $Requirements.MaximumActivationDuration
        $result.Mode=if($enforce){'EnforceExplicitRequirements'}else{'ReportOnly'}
        Assert-CadmScopeTenant -Scope $Scope
        $policies=@(Invoke-CadmRestAll -Url "$ArmBase$Scope/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=$PimApi")
        $matches=@($policies | Where-Object {
            (Get-RoleDefGuid ([string](Get-CadmField (Get-CadmField $_ 'properties') 'roleDefinitionId'))) -ieq $RoleDefinitionId
        })
        if($matches.Count -ne 1){throw 'Cannot uniquely determine the Azure role activation policy.'}
        $properties=Get-CadmField $matches[0] 'properties'
        $result.PolicyId=Get-CadmField $properties 'policyId'
        $rules=@(Get-CadmField $properties 'effectiveRules')
        $selected=[ordered]@{}
        foreach($id in @('Enablement_EndUser_Assignment','Approval_EndUser_Assignment','Expiration_EndUser_Assignment')){
            $match=@($rules | Where-Object {(Get-CadmField $_ 'id') -eq $id})
            if($match.Count -ne 1){throw "Activation rule is missing or ambiguous: $id"}
            $rule=$match[0];$target=Get-CadmField $rule 'target'
            if($target.caller -ne 'EndUser' -or $target.level -ne 'Assignment' -or @($target.operations) -notcontains 'All'){
                throw "Unexpected activation-rule target: $id"
            }
            $selected[$id]=$rule
        }
        $enabled=$selected['Enablement_EndUser_Assignment'].enabledRules
        if($enabled -isnot [System.Collections.IList]){throw 'Activation enablement rules are unreadable.'}
        $result.MfaRequired=@($enabled) -contains 'MultiFactorAuthentication'
        $setting=Get-CadmField $selected.Approval_EndUser_Assignment 'setting'
        $approval=Get-CadmField $setting 'isApprovalRequired'
        if($approval -isnot [bool]){throw 'Activation approval requirement is unreadable.'}
        $result.ApprovalRequired=$approval
        $stages=@(Get-CadmField $setting 'approvalStages')
        $configured=$stages.Count -gt 0
        foreach($stage in $stages){
            $valid=@($stage.primaryApprovers | Where-Object {
                $id=[guid]::Empty
                $_.userType -in @('User','Group') -and [guid]::TryParse([string]$_.id,[ref]$id) -and $id -ne [guid]::Empty
            })
            if(-not $valid.Count){$configured=$false}
        }
        $result.ApproversConfigured=$configured
        $expiration=$selected.Expiration_EndUser_Assignment
        if($expiration.isExpirationRequired -isnot [bool]){throw 'Activation expiration requirement is unreadable.'}
        $result.ExpirationRequired=$expiration.isExpirationRequired
        $result.MaximumActivationDuration=[string]$expiration.maximumDuration
        $span=ConvertTo-CadmTimeSpan $result.MaximumActivationDuration
        if(-not $span -or $span -le [timespan]::Zero){throw 'Activation maximum duration is missing or invalid.'}
        $auth=@($rules | Where-Object {(Get-CadmField $_ 'id') -eq 'AuthenticationContext_EndUser_Assignment'})
        if($auth.Count -gt 1){throw 'Authentication-context rule is ambiguous.'}
        if($auth.Count){$result.AuthenticationContextEnabled=Get-CadmField $auth[0] 'isEnabled'}
        if($Requirements.RequireMfa -and -not $result.MfaRequired){
            $result.Reasons+='The PIM activation rule does not explicitly require MFA. Authentication context/Conditional Access is not evaluated by this ARM-only check.'
        }
        if($Requirements.RequireApproval -and -not $result.ApprovalRequired){$result.Reasons+='Activation approval is not required.'}
        if($Requirements.RequireApproval -and $result.ApprovalRequired -and -not $result.ApproversConfigured){$result.Reasons+='Approval is enabled but every stage must name at least one valid primary user or group approver.'}
        if($Requirements.MaximumActivationDuration -and -not $result.ExpirationRequired){$result.Reasons+='Activation expiration is not required.'}
        if($Requirements.MaximumActivationDuration -and $span -gt (ConvertTo-CadmTimeSpan $Requirements.MaximumActivationDuration)){
            $result.Reasons+="Activation maximum $($result.MaximumActivationDuration) exceeds the configured limit $($Requirements.MaximumActivationDuration)."
        }
        $sha=[Security.Cryptography.SHA256]::Create()
        try{
            $bytes=[Text.Encoding]::UTF8.GetBytes(($selected | ConvertTo-Json -Depth 20 -Compress))
            $result.PolicyFingerprint=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
        }finally{$sha.Dispose()}
        $result.Status=if($result.Reasons.Count){'Fail'}elseif($enforce){'Pass'}else{'Observed'}
    }catch{$result.Status='Unknown';$result.Reasons+= $_.Exception.Message}
    return [pscustomobject]$result
}
function Show-CadmActivationChecks {
    param($Rows)
    $checks=@($Rows | Where-Object Plane -eq 'PIM-RES' | ForEach-Object {$_.ActivationCheck} | Where-Object {$null -ne $_})
    if(-not $checks.Count){return}
    Write-Host 'Azure activation policy settings (read-only; local requirements apply only when explicitly configured):'
    $checks | Select-Object Mode,Status,MfaRequired,ApprovalRequired,ApproversConfigured,MaximumActivationDuration,Scope | Format-Table -Wrap | Out-Host
    foreach($check in $checks){
        foreach($reason in $check.Reasons){Write-Host "  [$($check.Status)] $($check.RoleDefinitionId) @ $($check.Scope): $reason"}
    }
    Write-Host 'Approver identities are configured IDs only; their availability, group membership, and Conditional Access behavior are not verified.'
}
