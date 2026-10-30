import os, shutil, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = r'''
$script:planCalls=0;$script:submitted=$false
$script:expectedStart=[datetimeoffset]::UtcNow.ToString('o')
$script:expectedEnd=([datetimeoffset]$script:expectedStart).AddDays(365).ToString('o')
$ArmBase='https://management.azure.com';$PimApi='2020-10-01';$script:LastAzError=$null
function Initialize-AzInvoker {}
function Assert-CadmAzContext {}
function Assert-CadmScopeTenant {param($Scope)}
function Invoke-AzJson {param($AzArgs) @{user=@{name='operator@example.com'}}}
function Resolve-CadmUser {param($Ref) @{id='22222222-2222-2222-2222-222222222222';userPrincipalName='person-cadm@example.com';displayName='Person CADM';accountEnabled=$true}}
function Get-Subscriptions {return @()}
function Get-CadmField {param($Object,$Name) $Object.$Name}
function Get-RoleDefGuid {param($Value) ($Value -split '/')[-1]}
function Test-CadmConditionalAssignment {param($Record) [bool]$Record.condition}
function ConvertTo-CadmEligibilityDate {param($Value) [datetimeoffset]$Value}
function ConvertTo-CadmTimeSpan {param($Value) [System.Xml.XmlConvert]::ToTimeSpan($Value)}
function Read-Host {param($Prompt) if($env:WORKFLOW_SCENARIO -eq 'cancel'){'cancel'}else{'APPLY person-cadm@example.com'}}
function Invoke-CadmRestAll {param($Url)
 if($env:WORKFLOW_SCENARIO -eq 'read-error'){throw '403'}
 if($script:submitted -and $env:WORKFLOW_SCENARIO -ne 'partial') {
 @{id='assignment-id';properties=@{principalId='22222222-2222-2222-2222-222222222222';scope='/providers/Microsoft.Management/managementGroups/example';roleDefinitionId='/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c';status=$(if($env:WORKFLOW_SCENARIO -eq 'pending'){'PendingApproval'}else{'Provisioned'});startDateTime=$script:expectedStart;endDateTime=$script:expectedEnd}}
 }
}
'''
PROFILE = r'''
function Import-CadmTenant {param($TenantsDir)
 @{TenantId='11111111-1111-1111-1111-111111111111';Path=(Join-Path $PSScriptRoot 'tenant.psd1');ProfilesDir=$PSScriptRoot;DefaultEligibilityDuration='P365D';JustificationPrefix='Test';ScopeTokens=@{'example-mg'='/providers/Microsoft.Management/managementGroups/example'}}
}
function Get-CadmProfiles {param($ProfilesDir)
 $data=@{Metadata=@{SchemaVersion='1';Version='1.0.0';Owner='Team';Purpose='Test';ReviewDate=[datetime]::UtcNow.AddDays(60).ToString('yyyy-MM-dd');Status='Reviewed';Reviewer='Operator'};PimResourceEligibilities=@(@{Scope='/providers/Microsoft.Management/managementGroups/example'})}
 @{Key='test';Name='Test';Description='Test';Data=$data;Path=(Join-Path $PSScriptRoot 'test.psd1')}
}
function Get-ProfileEntries {param($Value) @($Value|Where-Object {$null -ne $_})}
function Assert-ProfileSafe {param($Profile,$Tenant)}
function Resolve-ProfilePlan {param($Profile,$Target,$Tenant,$Subs)
 $script:planCalls++
 [pscustomobject]@{Plane='PIM-RES';Action=$(if($env:WORKFLOW_SCENARIO -like 'blocked*'){'BLOCKED-ACTIVATION-POLICY'}else{'CREATE'});Item='Contributor';Scope='/providers/Microsoft.Management/managementGroups/example';RoleDefinitionId='b24988ac-6180-42a0-ab88-20f7382dd24c';ScheduleInfo=@{startDateTime=$script:expectedStart;expiration=@{type='afterDuration';duration=$(if($env:WORKFLOW_SCENARIO -eq 'stale' -and $script:planCalls -gt 1){'P30D'}else{'P365D'})}}}
}
function Invoke-ProfileGrant {param($Rows,$Target,$Justification,$DefaultDuration,$TicketNumber,$TicketSystem)
 $script:submitted=$true
 if($env:WORKFLOW_SCENARIO -eq 'partial'){throw 'simulated transport error'}
 @{Ok=1;Fail=0;Requests=@(@{RequestId='request-id'});Entries=@(@{State='Submitted';ScheduleInfo=$Rows[0].ScheduleInfo})}
}
'''

@pytest.mark.parametrize('scenario,code,state', [('success',0,'Verified'),('cancel',0,'Cancelled'),('stale',1,None),('pending',1,'PendingOrUnknown'),('read-error',1,'PendingOrUnknown'),('partial',1,'Partial'),('preview',0,'Preview'),('compare',0,'Compare')])
@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
def test_real_workflow_entrypoint_offline(tmp_path, scenario, code, state, shell):
    import json
    script=tmp_path/'Start-CadmWorkflow.ps1'
    shutil.copyfile(ROOT/'scripts/cadm/Start-CadmWorkflow.ps1',script)
    lib=tmp_path/'lib';lib.mkdir()
    (lib/'CadmAccess.Core.ps1').write_text(CORE)
    (lib/'CadmProfile.ps1').write_text(PROFILE)
    (lib/'CadmExport.ps1').write_text('')
    (lib/'tenant.psd1').write_text('@{}')
    (lib/'test.psd1').write_text('@{}')
    shutil.copyfile(ROOT/'scripts/cadm/lib/CadmWorkflow.ps1',lib/'CadmWorkflow.ps1')
    shutil.copyfile(ROOT/'scripts/cadm/lib/CadmAudit.ps1',lib/'CadmAudit.ps1')
    for name in ('CadmActivation.ps1', 'CadmBackup.ps1'):
        shutil.copyfile(ROOT/'scripts/cadm/lib'/name,lib/name)
    out=tmp_path/'evidence'
    env=dict(os.environ,WORKFLOW_SCENARIO=scenario)
    command=[shell,'-NoProfile','-File',str(script),'-Action',{'preview':'Preview','compare':'Compare'}.get(scenario,'Apply'),'-ProfileName','test','-TargetUser','person-cadm@example.com','-OutDir',str(out),'-VerificationAttempts','1','-VerificationDelaySeconds','0']
    if scenario not in ('preview','compare'): command+=['-Apply']
    result=subprocess.run(command,env=env,text=True,capture_output=True)
    assert result.returncode==code,result.stdout+result.stderr
    if state in ('Preview','Compare'):
        assert not list(out.rglob('submissions.json'))
        if state=='Compare': assert list(out.rglob('comparison.json'))
    elif state is None:
        assert not list(out.rglob('submissions.json'))
        assert 'changed since review' in result.stderr
    elif state=='Cancelled':
        assert json.loads(next(out.rglob('review.json')).read_text(encoding='utf-8-sig'))['State']==state
        assert not list(out.rglob('submissions.json'))
    else:
        outcome=json.loads(next(out.rglob('outcome.json')).read_text(encoding='utf-8-sig'))
        assert outcome['State']==state
        journal=json.loads(next(out.rglob('submissions.json')).read_text(encoding='utf-8-sig'))
        assert journal['Entries'][0]['State']==('Failed' if scenario=='partial' else 'Submitted')
        if scenario=='success':
            assert outcome['Verification'][0]['Evidence'][0]['AssignmentId']=='assignment-id'
            assert journal['Entries'][0]['Receipt']['Requests'][0]['RequestId']=='request-id'
