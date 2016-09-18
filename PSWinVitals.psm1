Function Get-VitalStatistics {
    [CmdletBinding(DefaultParameterSetName='AllStatistics')]
    Param(
        [Parameter(ParameterSetName='Statistics')]
            [Switch]$ComponentStoreAnalysis,
        [Parameter(ParameterSetName='Statistics')]
            [Switch]$EnvironmentVariables,
        [Parameter(ParameterSetName='Statistics')]
            [Switch]$InstalledFeatures,
        [Parameter(ParameterSetName='Statistics')]
            [Switch]$InstalledPrograms,
        [Parameter(ParameterSetName='Statistics')]
            [Switch]$VolumeSummary
    )

    if ($PSCmdlet.ParameterSetName -eq 'AllStatistics' -or $VolumeSummary) {
        Write-Host -ForegroundColor Green "Retrieving volume summary ..." -NoNewline
        Get-Volume | ? { $_.DriveType -eq 'Fixed' } | Format-Table
        Write-Host ''
    }
    
    if ($PSCmdlet.ParameterSetName -eq 'AllStatistics' -or $ComponentStoreAnalysis) {
        Invoke-DISM -Operation AnalyzeComponentStore
    }
    
    if ($PSCmdlet.ParameterSetName -eq 'AllStatistics' -or $InstalledFeatures) {
        Write-Host -ForegroundColor Green "Retrieving installed features ..." -NoNewline
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue | Out-Null) {
            Get-WindowsFeature | ? { $_.Installed } | Format-Table
        } else {
            Write-Warning 'Unable to retrieve installed features as Get-WindowsFeature cmdlet not found.'
        }
        Write-Host ''
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllStatistics' -or $InstalledPrograms) {
        Write-Host -ForegroundColor Green "Retrieving installed programs ..." -NoNewline
        Get-InstalledPrograms | Sort -Property DisplayName | Format-Table -Property DisplayName, Publisher, DisplayVersion
        Write-Host ''
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllStatistics' -or $EnvironmentVariables) {
        Write-Host -ForegroundColor Green "Retrieving system environment variables ..." -NoNewline
        [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine) | Sort -Property Name | Format-Table
        Write-Host ''

        Write-Host -ForegroundColor Green "Retrieving user environment variables ..." -NoNewline
        [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User) | Sort -Property Name | Format-Table
        Write-Host ''
    }
}

Function Invoke-VitalChecks {
    [CmdletBinding(DefaultParameterSetName='AllChecks')]
    Param(
        [Parameter(ParameterSetName='Checks')]
            [Switch]$FileSystemScans,
        [Parameter(ParameterSetName='Checks')]
            [Switch]$SystemFileChecker,
        [Parameter(ParameterSetName='Checks')]
            [Switch]$ComponentStoreScan,
        [Switch]$VerifyOnly
    )

    if (!(Test-IsAdministrator)) {
        throw 'The checks this function runs require administrator privileges.'
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllChecks' -or $FileSystemScans) {
        if ($VerifyOnly) {
            Invoke-CHKDSK -VerifyOnly
        } else {
            Invoke-CHKDSK
        }
    }
    
    if ($PSCmdlet.ParameterSetName -eq 'AllChecks' -or $SystemFileChecker) {
        if ($VerifyOnly) {
            Invoke-SFC -VerifyOnly
        } else {
            Invoke-SFC
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllChecks' -or $ComponentStoreScan) {
        if ($VerifyOnly) {
            Invoke-DISM -Operation ScanHealth
        } else {
            Invoke-DISM -Operation RestoreHealth
        }
    }
}

Function Invoke-VitalUpdates {
    [CmdletBinding(DefaultParameterSetName='AllUpdates')]
    Param(
        [Parameter(ParameterSetName='Updates')]
            [Switch]$ComponentStoreCleanup,
        [Parameter(ParameterSetName='Updates')]
            [Switch]$PowerShellHelp,
        [Parameter(ParameterSetName='Updates')]
            [Switch]$SysinternalsSuite
    )

    if (!(Test-IsAdministrator)) {
        throw 'The updates this function performs require administrator privileges.'
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllUpdates' -or $PowerShellHelp) {
        Write-Host -ForegroundColor Green "PowerShell: Updating help ..."
        Update-Help -Force
        Write-Host ''
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllUpdates' -or $SysinternalsSuite) {
        Update-Sysinternals
    }

    if ($PSCmdlet.ParameterSetName -eq 'AllUpdates' -or $ComponentStoreCleanup) {
        Invoke-DISM -Operation StartComponentCleanup
    }
}

Function Get-InstalledPrograms {
    [CmdletBinding()]
    Param()

    $NativeRegPath = '\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $Wow6432RegPath = '\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    $InstalledPrograms = @(
        # Native applications installed system wide
        if (Test-Path "HKLM:$NativeRegPath") { Get-ChildItem "HKLM:$NativeRegPath" }
        # Native applications installed under the current user
        if (Test-Path "HKCU:$NativeRegPath") { Get-ChildItem "HKCU:$NativeRegPath" }
        # 32-bit applications installed system wide on 64-bit Windows
        if (Test-Path "HKLM:$Wow6432RegPath") { Get-ChildItem "HKLM:$Wow6432RegPath" }
        # 32-bit applications installed under the current user on 64-bit Windows
        if (Test-Path "HKCU:$Wow6432RegPath") { Get-ChildItem "HKCU:$Wow6432RegPath" }
    ) | # Get the properties of each uninstall key
    % { Get-ItemProperty $_.PSPath } |
    # Filter out all the uninteresting entries
    ? { $_.DisplayName -and
        !$_.SystemComponent -and
        !$_.ReleaseType -and
        !$_.ParentKeyName -and
    ($_.UninstallString -or $_.NoRemove) }

    return $InstalledPrograms
}

Function Invoke-CHKDSK {
    [CmdletBinding()]
    Param(
        [Switch]$VerifyOnly
    )

    $SupportedFileSystems = @('FAT', 'FAT16', 'FAT32', 'NTFS', 'NTFS4', 'NTFS5')
    $Volumes = Get-Volume | ? { $_.DriveType -eq 'Fixed' -and $_.FileSystem -in $SupportedFileSystems }

    foreach ($Volume in $Volumes) {
        $VolumePath = $Volume.Path.TrimEnd('\')
        if ($VerifyOnly) {
            Write-Host -ForegroundColor Green "CHKDSK: Running verify-only scan on $VolumePath ..."
            & CHKDSK "$VolumePath"
        } else {
            Write-Host -ForegroundColor Green "CHKDSK: Running scan on $VolumePath ..."
            & CHKDSK "$VolumePath" /F
        }

        switch ($LASTEXITCODE) {
            0       { continue }
            2       { Write-Host -ForegroundColor Yellow "CHKDSK: Volume requires cleanup." }
            3       { Write-Host -ForegroundColor Red "CHKDSK: Volume contains errors." }
            default { Write-Host -ForegroundColor Red "CHKDSK: Unexpected exit code ($LASTEXITCODE)." }
        }
        Write-Host ''
    }
}

Function Invoke-DISM {
    [CmdletBinding()]
    Param(
        [ValidateSet('AnalyzeComponentStore', 'RestoreHealth', 'ScanHealth', 'StartComponentCleanup')]
            [String]$Operation
    )


    Write-Host -ForegroundColor Green "DISM: Running $Operation operation ..." -NoNewline
    & DISM /Online /Cleanup-Image /$Operation

    switch ($LASTEXITCODE) {
        0       { continue }
        default { Write-Host -ForegroundColor Red "DISM: Returned non-zero exit code ($LASTEXITCODE)." }
    }
    Write-Host ''
}

Function Invoke-SFC {
    [CmdletBinding()]
    Param(
        [Switch]$VerifyOnly
    )

    if ($VerifyOnly) {
        Write-Host -ForegroundColor Green "SFC: Running verify-only scan ..." -NoNewline
        & SFC /VERIFYONLY
    } else {
        Write-Host -ForegroundColor Green "SFC: Running scan ..." -NoNewline
        & SFC /SCANNOW
    }

    switch ($LASTEXITCODE) {
        0       { continue }
        default { Write-Host -ForegroundColor Red "SFC: Returned non-zero exit code ($LASTEXITCODE)." }
    }
    Write-Host ''
}

Function Test-IsAdministrator {
    [CmdletBinding()]
    Param()

    $User = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($User.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        return $true
    }
    return $false
}

Function Update-Sysinternals {
    [CmdletBinding()]
    Param()

    $SuiteUrl = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    $ZipPath  = "$env:TEMP\SysinternalsSuite.zip"
    $DestPath = "${env:ProgramFiles(x86)}\Sysinternals"

    Write-Host -ForegroundColor Green "Sysinternals: Retrieving latest version ..."
    Invoke-WebRequest -Uri $SuiteUrl -OutFile $ZipPath

    Write-Host -ForegroundColor Green "Sysinternals: Decompressing archive ..."
    Remove-Item -Path "$DestPath\*" -Recurse
    Expand-Archive -Path $ZipPath -DestinationPath $DestPath
    Remove-Item -Path $ZipPath

    $Version = (Get-ChildItem $DestPath | Sort -Property LastWriteTime | Select -Last 1).LastWriteTime.ToString('yyyyMMdd')
    Write-Host -ForegroundColor Green "Sysinternals: Installed version $Version."
    Write-Host ''
}
