#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmExport.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmWorkflow.ps1')
$script:passed=0
function Check($Name,[scriptblock]$Test){ & $Test; $script:passed++;Write-Host "PASS $Name" }
function Assert($Value){if(-not $Value){throw 'Assertion failed'}}
function Refuses([scriptblock]$Test){$threw=$false;try{&$Test|Out-Null}catch{$threw=$true};Assert $threw}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('workflow-test-'+[guid]::NewGuid());New-Item -ItemType Directory $temp|Out-Null
$tenant=@{TenantId='11111111-1111-1111-1111-111111111111';ScopeTokens=@{'example-mg'='/providers/Microsoft.Management/managementGroups/example'};ProfilesDir=$temp}
$data=@{Name='Test';Description='Test';Metadata=@{SchemaVersion='1';Version='1.0.0';Owner='Team';Purpose='Operations';Status='Draft';ReviewDate=[datetime]::UtcNow.AddDays(90).ToString('yyyy-MM-dd')};PimResourceEligibilities=@(@{RoleDefinitionId='b24988ac-6180-42a0-ab88-20f7382dd24c';Scope='template-scope';Duration='P365D'})}
Check 'Approved scope binds portable template' {Assert ((Set-WorkflowScope $tenant 'example-mg') -eq '/providers/Microsoft.Management/managementGroups/example')}
Check 'Unconfigured scope refused' {Refuses {Set-WorkflowScope $tenant '/subscriptions/unapproved'}}
Check 'Draft preview permitted, draft apply refused' {Assert-WorkflowMetadata $data;Refuses {Assert-WorkflowMetadata $data -ForApply}}
Check 'Reviewed template requires reviewer' {$data.Metadata.Status='Reviewed';Refuses {Assert-WorkflowMetadata $data -ForApply};$data.Metadata.Reviewer='Operator';Assert-WorkflowMetadata $data -ForApply}
Check 'Expired review refused' {$old=$data.Metadata.ReviewDate;$data.Metadata.ReviewDate='2020-01-01';Refuses {Assert-WorkflowMetadata $data -ForApply};$data.Metadata.ReviewDate=$old}
Check 'Builder round trip and no overwrite' {$p=Save-WorkflowTemplate $data 'test' $tenant;$loaded=Import-PowerShellDataFile $p;Assert ($loaded.PimResourceEligibilities[0].Scope -eq 'template-scope');Refuses {Save-WorkflowTemplate $data 'test' $tenant}}
Check 'Unknown keys refused' {$data.Bad=$true;Refuses {Save-WorkflowTemplate $data 'bad' $tenant};$data.Remove('Bad')}
Check 'Duplicate roles refused' {$data.PimResourceEligibilities+=,$data.PimResourceEligibilities[0];Refuses {Save-WorkflowTemplate $data 'duplicate' $tenant};$data.PimResourceEligibilities=@($data.PimResourceEligibilities[0])}
Check 'Traversal filename refused' {Refuses {Save-WorkflowTemplate $data '../escape' $tenant}}
Check 'Unknown resource keys refused' {$data.PimResourceEligibilities[0].Typo='yes';Refuses {Save-WorkflowTemplate $data 'typo' $tenant};$data.PimResourceEligibilities[0].Remove('Typo')}
function Resolve-CadmUser {param($Ref) @{id='22222222-2222-2222-2222-222222222222';userPrincipalName='person-cadm@example.com';accountEnabled=$true}}
Check 'Exact account required; prefix and mismatched UPN refused' {Refuses {Resolve-WorkflowUser 'person'};Refuses {Resolve-WorkflowUser 'other@example.com'};Assert ((Resolve-WorkflowUser 'person-cadm@example.com').accountEnabled)}
$scope='/providers/Microsoft.Management/managementGroups/example';$role='b24988ac-6180-42a0-ab88-20f7382dd24c'
$target=@{id='22222222-2222-2222-2222-222222222222'}
$row=[pscustomobject]@{Plane='PIM-RES';Action='CREATE';Item='Contributor';Scope=$scope;RoleDefinitionId=$role;AccessId='';ScheduleInfo=@{expiration=@{duration='P365D'}}}
function Assert-CadmScopeTenant {param($Scope)}
$script:records=@();$script:readFail=$false
function Invoke-CadmRestAll {param($Url) if($script:readFail){throw '403'};return $script:records}
function Resolve-ProfilePlan {param($Profile,$Target,$Tenant,$Subs) return @($row)}
Check 'Missing assignment remains pending' {$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -eq 'Pending')}
$record=@{id='assignment';properties=@{principalId=$target.id;scope=$scope;roleDefinitionId="/providers/Microsoft.Authorization/roleDefinitions/$role";status='Provisioned';startDateTime=[datetimeoffset]::UtcNow.AddHours(-1).ToString('o');endDateTime=[datetimeoffset]::UtcNow.AddDays(10).ToString('o')}}
$script:records=@($record)
Check 'Provisioned assignment and actual expiry verified' {$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -eq 'Provisioned');Assert ($v[0].Evidence[0].EndDateTime -eq $record.properties.endDateTime)}
Check 'Expiring eligibility classified' {$v=@(Get-WorkflowResourceReport @($row) $target);Assert ($v[0].Classification -eq 'Expiring')}
Check 'Pending Azure status is not success' {$record.properties.status='PendingApproval';$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -eq 'Pending');$record.properties.status='Provisioned'}
Check 'Expired eligibility is not verified' {$saved=$record.properties.endDateTime;$record.properties.endDateTime='2020-01-01T00:00:00Z';$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -ne 'Provisioned');$record.properties.endDateTime=$saved}
Check 'Conditional eligibility is not verified' {$record.properties.condition='restriction';$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -ne 'Provisioned');$record.properties.Remove('condition')}
Check 'Read error stays Unknown' {$script:readFail=$true;$v=@(Get-WorkflowVerification @($row) $target @{} $tenant @());Assert ($v[0].Status -eq 'Unknown');$script:readFail=$false}
Check 'Extra direct eligibility reported without removal' {$record.properties.roleDefinitionId='/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635';$v=@(Get-WorkflowResourceReport @($row) $target);Assert ($v[0].Classification -eq 'Extra')}
Check 'Foreign principals/scopes excluded' {$record.properties.principalId='foreign';Assert (@(Get-WorkflowResourceReport @($row) $target).Count -eq 0)}
Check 'Changed policy term changes reviewed fingerprint' {$before=Get-WorkflowFingerprint @($row);$row.ScheduleInfo.expiration.duration='P30D';Assert ($before -cne (Get-WorkflowFingerprint @($row)))}
Write-Host "$script:passed workflow checks passed. Offline mocks only."
