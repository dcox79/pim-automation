#requires -Version 5.1
# Local recovery copies only. No Azure, Graph, Git, or third-party service calls.
function Backup-CadmProfileFiles {
    param([hashtable]$Tenant,[string[]]$ProfilePaths,[string]$Reason='Manual')
    if(-not $Tenant.Path -or -not $Tenant.ProfilesDir){throw 'Backup requires tenant configuration and profiles paths.'}
    $tenantPath=[IO.Path]::GetFullPath($Tenant.Path)
    $profileRoot=[IO.Path]::GetFullPath($Tenant.ProfilesDir).TrimEnd('\','/')
    $backupRoot=Join-Path (Split-Path -Parent $tenantPath) 'backups'
    $run=Join-Path $backupRoot ([datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
    $sources=@(@{Source=$tenantPath;Name='tenant.psd1'})
    foreach($path in @($ProfilePaths | Sort-Object -Unique)){
        $full=[IO.Path]::GetFullPath($path)
        if((Split-Path -Parent $full).TrimEnd('\','/') -ine $profileRoot -or [IO.Path]::GetExtension($full) -ine '.psd1'){
            throw 'Only direct PSD1 profiles inside this tenant profiles directory can be backed up.'
        }
        $sources+=@{Source=$full;Name=('profile-'+[IO.Path]::GetFileName($full))}
    }
    $manifest=[ordered]@{SchemaVersion='1';State='Creating';CreatedUtc=[datetimeoffset]::UtcNow.ToString('o');TenantId=$Tenant.TenantId;Reason=$Reason;Files=@()}
    New-Item -ItemType Directory -Path $run -ErrorAction Stop | Out-Null
    try{
        foreach($source in $sources){
            # Copy exactly the bytes read; never serialize PSD1 because that would discard comments.
            $bytes=[IO.File]::ReadAllBytes($source.Source)
            $sha=[Security.Cryptography.SHA256]::Create()
            try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}
            $dest=Join-Path $run $source.Name
            $stream=[IO.File]::Open($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
            if((Get-CadmFileHash $dest) -cne $hash){throw 'Backup verification failed.'}
            $manifest.Files+=@{SourcePath=$source.Source;BackupFile=$source.Name;Sha256=$hash;Bytes=$bytes.Length}
        }
        $manifest.State='Complete'
        Write-CadmAudit $manifest (Join-Path $run 'manifest.json')
    }catch{
        $manifest.State='Failed';$manifest.Error=$_.Exception.Message
        Write-CadmAudit $manifest (Join-Path $run 'manifest.json')
        throw
    }
    return [pscustomobject]@{Path=$run;ManifestPath=(Join-Path $run 'manifest.json');Files=$manifest.Files}
}
