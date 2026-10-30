#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'scripts/cadm/lib/CadmAccess.Core.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmProfile.ps1')
. (Join-Path $root 'scripts/cadm/lib/CadmTui.ps1')
$script:passed=0
function Assert($value,[string]$message='Assertion failed'){if(-not $value){throw $message}}
function Refuses([scriptblock]$action){$threw=$false;try{&$action | Out-Null}catch{$threw=$true};Assert $threw 'Expected refusal'}
function Invoke-AzJsonRaw {throw 'Unexpected live CLI call'}
function Invoke-MgGraphRequest {throw 'Unexpected live Graph call'}
function Check($Name,[scriptblock]$Test){
    & {
        $script:TuiRoot=Join-Path $root 'scripts/cadm'
        $script:TuiOutDir=Join-Path ([IO.Path]::GetTempPath()) ('cadm-tui-'+[guid]::NewGuid())
        $script:TuiConnectGraph=$false;$script:TuiGroupCoverage=$false
        $script:answers=[Collections.Generic.Queue[string]]::new()
        $script:messages=@();$script:commands=@();$script:exitCode=0
        $script:user=@{id='22222222-2222-2222-2222-222222222222';userPrincipalName='admin@example.com';displayName='Test Admin';accountEnabled=$true}
        $script:tenant=@{Name='Example';TenantId='11111111-1111-1111-1111-111111111111';ProfilesDir=$script:TuiOutDir;ScopeTokens=@{'root-mg'='/providers/Microsoft.Management/managementGroups/example'}}
        $script:profiles=@(@{Key='owner-pim';Name='Owner via PIM';Description='Eligible Owner';Path='synthetic.psd1';Data=@{PimResourceEligibilities=@(@{Scope=$script:tenant.ScopeTokens['root-mg']})}})
        function Read-Host {param($Prompt) if(-not $script:answers.Count){throw "Unexpected prompt: $Prompt"};$script:answers.Dequeue()}
        function Write-Host {param($Object) $script:messages+=,[string]$Object}
        function Set-Answers {param([string[]]$Values) foreach($v in $Values){$script:answers.Enqueue($v)}}
        function Get-CadmTuiContext {return $script:tenant}
        function Get-CadmProfiles {param($ProfilesDir) return $script:profiles}
        function Resolve-CadmUser {param($Ref) return $script:user}
        function Invoke-CadmTuiCommand {param($ScriptName,$Arguments)
            $script:commands+=@{Script=$ScriptName;Arguments=$Arguments.Clone()}
            return $script:exitCode
        }
        & $Test
    }
    $script:passed++;Write-Host "PASS $Name"
}
Check 'Invalid menu input retries and Back cancels' {
    Set-Answers @('bad','9','0','b')
    Assert ((Read-CadmTuiChoice 'Test' @('One','Two')) -eq -1)
    Assert ($script:answers.Count -eq 0)
}
Check 'Preview selects a profile and exact account with no Apply or Graph sign-in' {
    Set-Answers @('1','admin@example.com','1')
    Invoke-CadmTuiProfile
    Assert ($script:commands.Count -eq 1)
    $p=$script:commands[0].Arguments
    Assert ($p.Mode -eq 'profile' -and $p.TargetUser -eq $script:user.id)
    Assert (-not $p.Apply -and -not $p.ConnectGraph -and -not $p.ContainsKey('Force'))
}
Check 'Back from profile selection performs no operation' {
    Set-Answers @('b')
    Invoke-CadmTuiProfile -Apply
    Assert ($script:commands.Count -eq 0)
}
Check 'Apply always previews first and requires account confirmation in backend' {
    Set-Answers @('1','admin@example.com','1','1')
    Invoke-CadmTuiProfile -Apply
    Assert ($script:commands.Count -eq 2)
    Assert (-not $script:commands[0].Arguments.Apply)
    Assert ($script:commands[1].Arguments.Apply -and $script:commands[1].Arguments.ConfirmTarget)
    Assert (-not $script:commands[1].Arguments.ContainsKey('Force'))
}
Check 'Cancelled apply remains a preview' {
    Set-Answers @('1','admin@example.com','1','b')
    Invoke-CadmTuiProfile -Apply
    Assert ($script:commands.Count -eq 1 -and -not $script:commands[0].Arguments.Apply)
}
Check 'Blocked preview never reaches apply or asks for confirmation' {
    $script:exitCode=2
    Set-Answers @('1','admin@example.com','1')
    Invoke-CadmTuiProfile -Apply
    Assert ($script:commands.Count -eq 1 -and $script:answers.Count -eq 0)
}
Check 'Portable profiles use configured scopes and the existing reviewed workflow' {
    $script:profiles[0].Data.PimResourceEligibilities[0].Scope='template-scope'
    Set-Answers @('1','admin@example.com','1','1','1')
    Invoke-CadmTuiProfile -Apply
    Assert ($script:commands[0].Script -eq 'Start-CadmWorkflow.ps1')
    Assert ($script:commands[0].Arguments.Action -eq 'Preview')
    Assert ($script:commands[1].Arguments.Action -eq 'Apply')
    Assert ($script:commands[1].Arguments.ScopeToken -eq 'root-mg')
}
Check 'Azure-only export preserves default expiry and does not request writes' {
    Set-Answers @('admin@example.com','1','1','1','../bad','con','new-profile')
    Invoke-CadmTuiExport
    Assert ($script:commands.Count -eq 1)
    $p=$script:commands[0].Arguments
    Assert ($p.Mode -eq 'export' -and $p.ProfileName -eq 'new-profile')
    Assert ($p.ExportPlanes.Count -eq 1 -and $p.ExportPlanes[0] -eq 'AzureResource')
    Assert (-not $p.ConnectGraph -and -not $p.ContainsKey('Apply') -and -not $p.ContainsKey('EligibilityDuration'))
}
Check 'Export supports explicit broader scopes without changing activation policy' {
    Set-Answers @('admin@example.com','1','1','3','1','wide-profile')
    Invoke-CadmTuiExport
    Assert ($script:commands[0].Arguments.AdditionalScopes[0] -eq 'root-mg')
    Assert (-not $script:commands[0].Arguments.ContainsKey('ActivationRequirements'))
}
Check 'Name search escapes OData and requires a numbered account selection' {
    $script:seenUrl=$null
    function Invoke-CadmRestAll {param($Url) $script:seenUrl=$Url;return @($script:user)}
    Set-Answers @("O'Connor",'1')
    $user=Select-CadmTuiUser 'Source'
    Assert ($user.id -eq $script:user.id)
    Assert ([uri]::UnescapeDataString($script:seenUrl).Contains("O''Connor"))
    Assert ($script:commands.Count -eq 0)
}
Check 'Exact UPN mismatch is refused instead of choosing a similar account' {
    Set-Answers @('different@example.com')
    Refuses {Select-CadmTuiUser 'Target'}
    Assert ($script:commands.Count -eq 0)
}
Check 'Disabled account cannot be selected for apply' {
    $script:user.accountEnabled=$false
    Set-Answers @('admin@example.com','1','b')
    Assert ($null -eq (Select-CadmTuiUser 'Target'))
}
Check 'Control characters in labels cannot emit terminal escape sequences' {
    $label=Format-CadmTuiText ("Name"+[char]27+"[2J"+[char]10+"next")
    Assert ($label -notmatch '[\x00-\x1f\x7f]')
}
Check 'Main menu survives failed operation and returns to Quit' {
    function Invoke-CadmTuiProfile {throw 'Simulated read error'}
    Set-Answers @('1','b')
    Start-CadmTuiLoop -Root $script:TuiRoot -OutDir $script:TuiOutDir
    Assert (($script:messages -join ' ') -match 'Simulated read error')
    Assert ($script:answers.Count -eq 0)
}
Check 'Changing options starts no cloud session or operation' {
    Set-Answers @('7','2','7','4','b')
    Start-CadmTuiLoop -Root $script:TuiRoot -OutDir $script:TuiOutDir
    Assert ($script:TuiConnectGraph -and $script:TuiGroupCoverage)
    Assert ($script:commands.Count -eq 0)
}
Check 'Quit never requires Azure login' {
    function Initialize-AzInvoker {throw 'Must not initialize Azure'}
    Set-Answers @('b')
    Start-CadmTuiLoop -Root $script:TuiRoot -OutDir $script:TuiOutDir
    Assert ($script:commands.Count -eq 0)
}
Write-Host "$script:passed TUI checks passed. Offline mocks only."
