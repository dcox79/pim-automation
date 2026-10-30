#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmTui.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmSetup.ps1')
function Initialize-AzInvoker {throw 'Setup must stay offline'}
function Invoke-AzJson {throw 'Setup must stay offline'}
function Invoke-Rest {throw 'Setup must stay offline'}
function Invoke-MgJson {throw 'Setup must stay offline'}
function Assert($value,[string]$message='Assertion failed'){if(-not $value){throw $message}}
function Refuses([scriptblock]$action){$threw=$false;try{& $action | Out-Null}catch{$threw=$true};Assert $threw 'Expected refusal'}
$testRoot=Join-Path $root ('reports/setup-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $testRoot -Force
$script:passed=0
function Check($Name,[scriptblock]$Test){
    & {
        $caseRoot=Join-Path $testRoot ([guid]::NewGuid().ToString('N').Substring(0,8))
        $tenants=Join-Path $caseRoot 'tenants'
        $null=New-Item -ItemType Directory -Path $tenants -Force
        $params=@{TenantsDir=$tenants;Key='new-tenant';Name='Test Tenant';TenantId='11111111-1111-1111-1111-111111111111';Scope='/subscriptions/22222222-2222-2222-2222-222222222222';DefaultDays=30}
        $script:TuiRoot=$caseRoot
        $script:answers=[Collections.Generic.Queue[string]]::new()
        function Read-Host {param($Prompt) if(-not $script:answers.Count){throw "Unexpected prompt: $Prompt"};$script:answers.Dequeue()}
        function Set-Answers {param([string[]]$Values) foreach($v in $Values){$script:answers.Enqueue($v)}}
        & $Test
    }
    $script:passed++;Write-Host "PASS $Name"
}
Check 'Configuration only round-trips with no added activation requirements' {
    $result=New-CadmTenantConfiguration @params
    $t=Import-PowerShellDataFile -LiteralPath $result.Path
    Assert ($t.TenantId -eq $params.TenantId)
    Assert ($t.ScopeTokens['default-scope'] -eq $params.Scope)
    Assert ($t.DefaultEligibilityDuration -eq 'P30D')
    Assert ($t.ActivationRequirements.Count -eq 0)
    Assert (@(Get-ChildItem -LiteralPath $result.ProfilesDir).Count -eq 0)
}
Check 'Optional Reader profile passes existing validation and grants nothing at creation' {
    $result=New-CadmTenantConfiguration @params -ReaderProfile
    $t=Import-PowerShellDataFile -LiteralPath $result.Path
    $profile=@(Get-CadmProfiles $result.ProfilesDir)[0]
    Assert-ProfileSafe -Profile $profile -Tenant $t
    Assert ($profile.Data.Rbac[0].Role -eq 'Reader')
    Assert ($profile.Data.Rbac[0].Scope -eq 'default-scope')
    Assert ($profile.Data.PimResourceEligibilities.Count -eq 0)
    Assert ($profile.Description -match 'without PIM activation')
}
Check 'Quoted display names remain literal data' {
    $params.Name='O''Brien $(throw "do not run")'
    $result=New-CadmTenantConfiguration @params -ReaderProfile
    Assert ((Import-PowerShellDataFile -LiteralPath $result.Path).Name -ceq $params.Name)
}
Check 'Existing folder and files are preserved' {
    $result=New-CadmTenantConfiguration @params
    $before=[IO.File]::ReadAllText($result.Path)
    Refuses {New-CadmTenantConfiguration @params -ReaderProfile}
    Assert ([IO.File]::ReadAllText($result.Path) -ceq $before)
    Assert (-not (Test-Path (Join-Path $result.ProfilesDir 'reader-only.psd1')))
}
Check 'Duplicate tenant ID is refused under another folder name' {
    $null=New-CadmTenantConfiguration @params
    $params.Key='another-name'
    Refuses {New-CadmTenantConfiguration @params}
    Assert (-not (Test-Path (Join-Path $tenants 'another-name')))
}
Check 'Traversal and reserved folder names are refused before writes' {
    foreach($key in @('../outside','a/b','example','con','nul','com1','UPPER')){
        $params.Key=$key
        Refuses {New-CadmTenantConfiguration @params}
    }
    Assert (@(Get-ChildItem -LiteralPath $tenants).Count -eq 0)
}
Check 'Invalid identities, scopes and durations are refused before writes' {
    $valid=$params.Clone()
    $params.TenantId='00000000-0000-0000-0000-000000000000'
    Refuses {New-CadmTenantConfiguration @params}
    $params=$valid.Clone();$params.Scope='/'
    Refuses {New-CadmTenantConfiguration @params}
    $params=$valid.Clone();$params.Scope='/subscriptions/../../escape'
    Refuses {New-CadmTenantConfiguration @params}
    $params=$valid.Clone();$params.DefaultDays=0
    Refuses {New-CadmTenantConfiguration @params}
    Assert (@(Get-ChildItem -LiteralPath $tenants).Count -eq 0)
}
Check 'Path redirection links are refused before writes' {
    function Get-Item {param($LiteralPath) [pscustomobject]@{LinkType='Junction';Target=@('C:\outside')}}
    Refuses {New-CadmTenantConfiguration @params}
    Assert (@(Get-ChildItem -LiteralPath $tenants).Count -eq 0)
}
Check 'Failed writing cannot publish a tenant binding' {
    function Write-CadmSetupFile {param($Path,$Text) throw 'Simulated disk failure'}
    Refuses {New-CadmTenantConfiguration @params}
    Assert (-not (Test-Path (Join-Path $tenants 'new-tenant/tenant.psd1')))
}
Check 'Wizard cancellation before save creates no files' {
    Set-Answers @('new-tenant','Test Tenant',$params.TenantId,'1','22222222-2222-2222-2222-222222222222','30','2','b')
    Invoke-CadmTuiSetup
    Assert (@(Get-ChildItem -LiteralPath $tenants).Count -eq 0)
    Assert ($script:answers.Count -eq 0)
}
Check 'Wizard can create Reader configuration offline' {
    Set-Answers @('new-tenant','Test Tenant',$params.TenantId,'2','test-mg','','2','1')
    Invoke-CadmTuiSetup
    $t=Import-PowerShellDataFile -LiteralPath (Join-Path $tenants 'new-tenant/tenant.psd1')
    Assert ($t.ScopeTokens['default-scope'] -eq '/providers/Microsoft.Management/managementGroups/test-mg')
    Assert ($t.DefaultEligibilityDuration -eq 'P365D')
    Assert (Test-Path (Join-Path $tenants 'new-tenant/profiles/reader-only.psd1'))
    Assert ($script:answers.Count -eq 0)
}
Check 'Wizard supports explicit root scope and exporting first profile later' {
    Set-Answers @('new-tenant','Test Tenant',$params.TenantId,'3','60','1','1')
    Invoke-CadmTuiSetup
    $t=Import-PowerShellDataFile -LiteralPath (Join-Path $tenants 'new-tenant/tenant.psd1')
    Assert ($t.ScopeTokens['default-scope'] -eq "/providers/Microsoft.Management/managementGroups/$($params.TenantId)")
    Assert (@(Get-ChildItem -LiteralPath (Join-Path $tenants 'new-tenant/profiles')).Count -eq 0)
}
Write-Host "$script:passed setup checks passed. Synthetic files only: $testRoot"

