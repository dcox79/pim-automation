#requires -Version 5.1
# Shared profile verification and durable per-assignment execution journal.
function Write-CadmAudit {
    param($Value, [string]$Path)
    $temp = "$Path.$([guid]::NewGuid()).tmp"
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($true))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp } }
}
function Test-CadmObservedTerm {
    param($Record, $Row)
    $start = ConvertTo-CadmEligibilityDate (Get-CadmField $Record 'startDateTime')
    $endValue = Get-CadmField $Record 'endDateTime'
    $end = if ($endValue) { ConvertTo-CadmEligibilityDate $endValue } else { $null }
    if ($end -and ($end -le [datetimeoffset]::UtcNow -or $end -le $start)) { return $false }
    # Existing eligibilities are observed, never silently renewed to match a template.
    if ($Row.Action -eq 'SKIP-EXISTS') { return $true }
    $schedule = Get-CadmField $Row 'ScheduleInfo'
    if (-not $schedule -or -not $schedule.startDateTime -or -not $end) { return $false }
    $expectedStart = ConvertTo-CadmEligibilityDate $schedule.startDateTime
    $expiration = $schedule.expiration
    if ($expiration.type -eq 'afterDateTime') { $expectedEnd = ConvertTo-CadmEligibilityDate $expiration.endDateTime }
    elseif ($expiration.type -eq 'afterDuration') {
        $duration = ConvertTo-CadmTimeSpan $expiration.duration
        if (-not $duration -or $duration -le [timespan]::Zero) { return $false }
        $expectedEnd = $expectedStart.Add($duration)
    } else { return $false }
    # Services can round schedule timestamps to seconds. Never accept materially longer terms.
    return [math]::Abs(($start - $expectedStart).TotalSeconds) -le 2 -and
           [math]::Abs(($end - $expectedEnd).TotalSeconds) -le 2
}
function Get-CadmProfileVerification {
    param([object[]]$Rows, $Target)
    foreach ($row in $Rows) {
        $status='Pending'; $detail='Assignment not observed yet'; $evidence=@()
        try {
            $matches=@()
            $filter = [uri]::EscapeDataString("principalId eq '$($Target.id)'")
            switch ($row.Plane) {
                'PIM-RES' {
                    Assert-CadmScopeTenant -Scope $row.Scope
                    $all=@(Invoke-CadmRestAll -Url ('{0}{1}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version={2}&$filter={3}' -f $ArmBase,$row.Scope,$PimApi,$filter))
                    foreach ($record in $all) {
                        $p=Get-CadmField $record 'properties'
                        if (-not $p -or -not $p.principalId -or -not $p.roleDefinitionId -or -not $p.scope) { throw 'Malformed Azure eligibility read-back.' }
                        if ($p.principalId -ieq $Target.id -and $p.scope -ieq $row.Scope -and (Get-RoleDefGuid $p.roleDefinitionId) -ieq $row.RoleDefinitionId) {
                            $matches+=@{Id=$record.id;Data=$p;Status=$p.status}
                        }
                    }
                }
                { $_ -in @('PIM-GRP','PIM-DIR') } {
                    $path=if($row.Plane -eq 'PIM-GRP'){'identityGovernance/privilegedAccess/group/eligibilityScheduleInstances'}else{'roleManagement/directory/roleEligibilityScheduleInstances'}
                    $result=Invoke-MgJsonAll -Uri ('{0}/{1}?$filter={2}' -f $GraphBase,$path,$filter)
                    if(-not $result.Ok){throw $result.Error}
                    foreach($record in $result.Value) {
                        if(-not $record.principalId){throw 'Malformed Graph eligibility read-back.'}
                        $same = if($row.Plane -eq 'PIM-GRP'){
                            if(-not $record.groupId -or -not $record.accessId){throw 'Malformed group eligibility read-back.'}
                            $record.groupId -ieq $row.Scope -and $record.accessId -eq $row.AccessId
                        }else{
                            if(-not $record.roleDefinitionId -or -not $record.directoryScopeId){throw 'Malformed directory eligibility read-back.'}
                            $record.roleDefinitionId -ieq $row.RoleDefinitionId -and $record.directoryScopeId -ieq $row.Scope -and -not $record.appScopeId
                        }
                        if($record.principalId -ieq $Target.id -and $same){$matches+=@{Id=$record.id;Data=$record;Status='InstanceObserved'}}
                    }
                }
                'RBAC' {
                    Assert-CadmScopeTenant -Scope $row.Scope
                    $all=@(Invoke-CadmRestAll -Url ('{0}{1}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter={2}' -f $ArmBase,$row.Scope,$filter))
                    foreach($record in $all){
                        $p=$record.properties
                        if(-not $p.principalId -or -not $p.roleDefinitionId -or -not $p.scope){throw 'Malformed RBAC read-back.'}
                        if($p.principalId -ieq $Target.id -and $p.scope -ieq $row.Scope -and (Get-RoleDefGuid $p.roleDefinitionId) -ieq $row.Detail){
                            $matches+=@{Id=$record.id;Data=$p;Status='InstanceObserved'}
                        }
                    }
                }
                'GROUP' {
                    # Direct member list: transitive membership cannot satisfy a direct-membership profile.
                    $result=Invoke-MgJsonAll -Uri ('{0}/groups/{1}/members?$select=id' -f $GraphBase,$row.Scope)
                    if(-not $result.Ok){throw $result.Error}
                    foreach($record in $result.Value){
                        if(-not $record.id){throw 'Malformed group membership read-back.'}
                        if($record.id -ieq $Target.id){$matches+=@{Id=$record.id;Data=$record;Status='InstanceObserved'}}
                    }
                }
                default {throw "Unsupported verification plane: $($row.Plane)"}
            }
            $valid=0
            foreach($match in $matches) {
                if(-not $match.Id){throw 'Read-back assignment ID is missing.'}
                $p=$match.Data
                $conditional=Test-CadmConditionalAssignment $p
                $termOk=if($row.Plane -like 'PIM-*'){Test-CadmObservedTerm -Record $p -Row $row}else{$true}
                $evidence+=@{AssignmentId=$match.Id;Status=$match.Status;StartDateTime=$p.startDateTime;EndDateTime=$p.endDateTime;Conditional=$conditional;TermMatches=$termOk}
                if($match.Status -in @('Failed','Denied','Canceled','Cancelled','Revoked')){$status='Failed';$detail='Service reports failed or revoked eligibility'}
                elseif(-not $conditional -and $termOk -and $match.Status -in @('Provisioned','InstanceObserved')){$valid++}
            }
            if($valid -eq 1 -and $matches.Count -eq 1){
                $status=if($row.Action -eq 'SKIP-EXISTS'){'Retained'}else{'Verified'}
                $detail=if($status -eq 'Retained'){'Existing assignment observed; its expiry is unchanged'}else{'Exact principal, role or membership, scope, and requested eligibility dates read back'}
            }elseif($matches.Count -and $status -ne 'Failed'){
                if(@($evidence | Where-Object {$_.Conditional -or -not $_.TermMatches}).Count -or $matches.Count -gt 1){
                    $status='Mismatch';$detail='Observed restrictions, dates, or duplicate assignments differ from the requested result'
                }else{$detail='Eligibility exists but provisioning is not complete'}
            }
        } catch {$status='Unknown';$detail=$_.Exception.Message}
        [pscustomobject]@{Plane=$row.Plane;Role=$row.Item;Scope=$row.Scope;RoleDefinitionId=(Get-CadmField $row 'RoleDefinitionId');AccessId=(Get-CadmField $row 'AccessId');Status=$status;Detail=$detail;Evidence=@($evidence)}
    }
}
function Invoke-CadmAuditedProfileApply {
    param([object[]]$Rows,$Target,[string]$Justification,[string]$DefaultDuration='P365D',
          [string]$TicketNumber,[string]$TicketSystem,[string]$RunDirectory,$Context,
          [ValidateRange(1,10)][int]$VerificationAttempts=3,[ValidateRange(0,30)][int]$VerificationDelaySeconds=5)
    $journal=[ordered]@{RunId=$Context.RunId;State='Approved';Entries=@();Ok=0;Fail=0}
    $submissionPath=Join-Path $RunDirectory 'submissions.json'
    $outcomePath=Join-Path $RunDirectory 'outcome.json'
    $fatal=$null; $verification=@();$verifyRows=@()
    # Persist every planned row before any cloud mutation, including rows retained unchanged.
    foreach($row in $Rows){
        $journal.Entries+=,[ordered]@{Plane=$row.Plane;Role=$row.Item;Scope=$row.Scope;Action=$row.Action;State=$(if($row.Action -eq 'CREATE'){'Planned'}else{'Retained'});Plan=$row;Receipt=$null;Error=$null;Events=@(@{State='Planned';TimestampUtc=[datetimeoffset]::UtcNow.ToString('o')})}
    }
    Write-CadmAudit $journal $submissionPath
    try {
        for($i=0;$i -lt $Rows.Count;$i++){
            $row=$Rows[$i];$entry=$journal.Entries[$i]
            if($row.Action -eq 'SKIP-EXISTS'){$verifyRows+=,$row;continue}
            if($row.Action -ne 'CREATE'){throw "Blocked plan action: $($row.Action)"}
            $entry.State='Submitting';$entry.Events+=@{State='Submitting';TimestampUtc=[datetimeoffset]::UtcNow.ToString('o')}
            $journal.State='Applying';Write-CadmAudit $journal $submissionPath
            try {
                $receipt=Invoke-ProfileGrant -Rows @($row) -Target $Target -Justification $Justification -DefaultDuration $DefaultDuration -TicketNumber $TicketNumber -TicketSystem $TicketSystem
                $entry.Receipt=$receipt
                $journal.Ok+=$receipt.Ok;$journal.Fail+=$receipt.Fail
                $entry.State=if($receipt.Fail){'Failed'}else{'Submitted'}
                if($receipt.Fail){$entry.Error=@($receipt.Entries | ForEach-Object {$_.Error}) -join '; '}
                # Read-back must compare with the schedule actually submitted at the write boundary.
                $detail=@($receipt.Entries | Select-Object -First 1)
                if($detail.Count -and $detail[0].ScheduleInfo){$row.ScheduleInfo=$detail[0].ScheduleInfo}
                if($detail.Count -and $detail[0].State -eq 'Retained'){$row.Action='SKIP-EXISTS';$entry.State='Retained'}
            }catch{$entry.State='Failed';$entry.Error=$_.Exception.Message;$journal.Fail++}
            $entry.Events+=@{State=$entry.State;TimestampUtc=[datetimeoffset]::UtcNow.ToString('o')}
            Write-CadmAudit $journal $submissionPath
            $verifyRows+=,$row
        }
    }catch{$fatal=$_.Exception.Message}
    finally {
        # Interrupted/unsubmitted entries remain explicitly NotSubmitted, never silently omitted.
        foreach($entry in $journal.Entries){if($entry.State -eq 'Planned'){$entry.State='NotSubmitted'}}
        for($attempt=1;$attempt -le $VerificationAttempts;$attempt++){
            try{$verification=@(Get-CadmProfileVerification -Rows $verifyRows -Target $Target)}
            catch{$fatal=$_.Exception.Message;break}
            if(-not @($verification | Where-Object Status -notin @('Verified','Retained')).Count){break}
            if($attempt -lt $VerificationAttempts -and $VerificationDelaySeconds){Start-Sleep -Seconds $VerificationDelaySeconds}
        }
        $complete=$verification.Count -eq $Rows.Count -and -not @($verification | Where-Object Status -notin @('Verified','Retained')).Count
        $state=if($fatal -or $journal.Fail){'Partial'}elseif($complete){'Verified'}else{'PendingOrUnknown'}
        $journal.State=$state
        for($i=0;$i -lt $verification.Count;$i++){
            $journal.Entries[$i].Verification=$verification[$i]
            $journal.Entries[$i].Events+=@{State=$verification[$i].Status;TimestampUtc=[datetimeoffset]::UtcNow.ToString('o')}
        }
        $outcome=[ordered]@{RunId=$Context.RunId;State=$state;CompletedUtc=[datetimeoffset]::UtcNow.ToString('o');Context=$Context;TargetId=$Target.id;Submission=$journal;Error=$fatal;Verification=$verification}
        Write-CadmAudit $journal $submissionPath
        Write-CadmAudit $outcome $outcomePath
    }
    return $outcome
}

function Get-CadmPlanFingerprint {
    param($Rows)
    return (@($Rows | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}' -f $_.Plane,$_.Action,$_.Item,$_.Scope,$_.RoleDefinitionId,$_.AccessId,$_.ScheduleInfo.expiration.duration,$_.ScheduleInfo.expiration.endDateTime,$_.StartDateTime,$_.Detail,$_.ActivationCheck.PolicyFingerprint
    } | Sort-Object) -join [Environment]::NewLine)
}

function Get-CadmFileHash {
    param([string]$Path)
    $stream=[IO.File]::OpenRead($Path);$algorithm=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','')}
    finally{$algorithm.Dispose();$stream.Dispose()}
}
