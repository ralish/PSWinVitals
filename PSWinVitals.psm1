Function Get-VitalStatistics {
    [CmdletBinding(DefaultParameterSetName='Statistics')]
    Param(
        [Parameter(ParameterSetName='All')]
        [Switch]$AllStatistics,

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

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ComponentStoreAnalysis = $true
        $EnvironmentVariables = $true
        $InstalledFeatures = $true
        $InstalledPrograms = $true
        $VolumeSummary = $true
    }

    if ($ComponentStoreAnalysis) {
        if (!(Test-IsAdministrator)) {
            throw 'You must have administrator privileges to analyse the component store.'
        }
    }

    $VitalStatistics = [PSCustomObject]@{
        ComponentStoreAnalysis = $null
        EnvironmentVariables = $null
        InstalledFeatures = $null
        InstalledPrograms = $null
        VolumeSummary = $null
    }

    if ($VolumeSummary) {
        Write-Verbose 'Retrieving volume summary ...'
        $VitalStatistics.VolumeSummary = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
    }
    
    if ($ComponentStoreAnalysis) {
        $VitalStatistics.ComponentStoreAnalysis = Invoke-DISM -Operation AnalyzeComponentStore
    }
    
    if ($InstalledFeatures) {
        Write-Verbose 'Retrieving installed features ...'
        if ($null = Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $VitalStatistics.InstalledFeatures = Get-WindowsFeature | Where-Object { $_.Installed }
        } else {
            Write-Warning 'Unable to retrieve installed features as Get-WindowsFeature cmdlet not found.'
        }
    }

    if ($InstalledPrograms) {
        Write-Verbose 'Retrieving installed programs ...'
        $VitalStatistics.InstalledPrograms = Get-InstalledPrograms
    }

    if ($EnvironmentVariables) {
        [PSCustomObject]$EnvironmentVariables = [PSCustomObject]@{
            Machine = $null
            User = $null
        }

        Write-Verbose 'Retrieving system environment variables ...'
        $EnvironmentVariables.Machine = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)

        Write-Verbose 'Retrieving user environment variables ...'
        $EnvironmentVariables.User = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)

        $VitalStatistics.EnvironmentVariables = $EnvironmentVariables
    }

    return $VitalStatistics
}

Function Invoke-VitalChecks {
    [CmdletBinding(DefaultParameterSetName='Checks')]
    Param(
        [Parameter(ParameterSetName='All')]
        [Switch]$AllChecks,

        [Parameter(ParameterSetName='Checks')]
        [Switch]$FileSystemScans,

        [Parameter(ParameterSetName='Checks')]
        [Switch]$SystemFileChecker,

        [Parameter(ParameterSetName='Checks')]
        [Switch]$ComponentStoreScan,

        [Switch]$VerifyOnly
    )

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ComponentStoreScan = $true
        $FileSystemScans = $true
        $SystemFileChecker = $true
    }

    if (!(Test-IsAdministrator)) {
        throw 'The checks this function performs require administrator privileges.'
    }

    $VitalChecks = [PSCustomObject]@{
        ComponentStoreScan = $null
        FileSystemScans = $null
        SystemFileChecker = $null
    }

    if ($FileSystemScans) {
        if ($VerifyOnly) {
            $VitalChecks.FileSystemScans = Invoke-CHKDSK -VerifyOnly
        } else {
            $VitalChecks.FileSystemScans = Invoke-CHKDSK
        }
    }
    
    if ($SystemFileChecker) {
        if ($VerifyOnly) {
            $VitalChecks.SystemFileChecker = Invoke-SFC -VerifyOnly
        } else {
            $VitalChecks.SystemFileChecker = Invoke-SFC
        }
    }

    if ($ComponentStoreScan) {
        if ($VerifyOnly) {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation ScanHealth
        } else {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation RestoreHealth
        }
    }

    return $VitalChecks
}

Function Invoke-VitalUpdates {
    [CmdletBinding(DefaultParameterSetName='Updates')]
    Param(
        [Parameter(ParameterSetName='All')]
        [Switch]$AllUpdates,

        [Parameter(ParameterSetName='Updates')]
        [Switch]$ComponentStoreCleanup,

        [Parameter(ParameterSetName='Updates')]
        [Switch]$PowerShellHelp,

        [Parameter(ParameterSetName='Updates')]
        [Switch]$SysinternalsSuite
    )

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ComponentStoreCleanup = $true
        $PowerShellHelp = $true
        $SysinternalsSuite = $true
    }

    if (!(Test-IsAdministrator)) {
        throw 'The updates this function performs require administrator privileges.'
    }

    $VitalUpdates = [PSCustomObject]@{
        ComponentStoreCleanup = $null
        PowerShellHelp = $null
        SysinternalsSuite = $null
    }

    if ($PowerShellHelp) {
        Write-Verbose 'PowerShell: Updating help ...'
        Update-Help -Force
        $VitalUpdates.PowerShellHelp = $true
    }

    if ($SysinternalsSuite) {
        $VitalUpdates.SysinternalsSuite = Update-Sysinternals
    }

    if ($ComponentStoreCleanup) {
        $VitalUpdates.ComponentStoreCleanup = Invoke-DISM -Operation StartComponentCleanup
    }

    return $VitalUpdates
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
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    # Filter out all the uninteresting entries
    Where-Object { $_.DisplayName -and
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
    $Volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -in $SupportedFileSystems }

    [String[]]$ChkDskResults = $null
    foreach ($Volume in $Volumes) {
        $VolumePath = $Volume.Path.TrimEnd('\')
        if ($VerifyOnly) {
            Write-Verbose "[CHKDSK] Running verify-only scan on $VolumePath ..."
            $ChkDskResults += & "$env:windir\System32\chkdsk.exe" "$VolumePath"
        } else {
            # TODO: Actually run a fix scan optimised based on OS version.
            Write-Verbose "[CHKDSK] Running scan on $VolumePath ..."
            $ChkDskResults += & "$env:windir\System32\chkdsk.exe" "$VolumePath"
        }

        switch ($LASTEXITCODE) {
            0       { continue }
            2       { Write-Warning "[CHKDSK]: Volume requires cleanup: $VolumePath" }
            3       { Write-Warning "[CHKDSK] Volume contains errors: $VolumePath" }
            default { Write-Error "[CHKDSK] Unexpected exit code '$LASTEXITCODE' while scanning volume: $VolumePath" }
        }
    }

    return $ChkDskResults
}

Function Invoke-DISM {
    [CmdletBinding()]
    Param(
        [ValidateSet('AnalyzeComponentStore', 'RestoreHealth', 'ScanHealth', 'StartComponentCleanup')]
        [String]$Operation
    )


    Write-Verbose "[DISM] Running $Operation operation ..."
    $DismResults = & "$env:windir\System32\dism.exe" /Online /Cleanup-Image /$Operation

    switch ($LASTEXITCODE) {
        0       { continue }
        default { Write-Error "[DISM] Returned non-zero exit code performing $Operation operation: $LASTEXITCODE" }
    }

    return $DismResults
}

Function Invoke-SFC {
    [CmdletBinding()]
    Param(
        [Switch]$VerifyOnly
    )

    if ($VerifyOnly) {
        Write-Verbose '[SFC] Running verify-only scan ...'
        $SfcResults = & "$env:windir\System32\sfc.exe" /VERIFYONLY
    } else {
        Write-Verbose '[SFC] Running scan ...'
        $SfcResults = & "$env:windir\System32\sfc.exe" /SCANNOW
    }

    switch ($LASTEXITCODE) {
        0       { continue }
        default { Write-Error "[SFC] Returned non-zero exit code: $LASTEXITCODE" }
    }

    return $SfcResults
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

    Write-Verbose '[Sysinternals] Retrieving latest version ...'
    Invoke-WebRequest -Uri $SuiteUrl -OutFile $ZipPath

    Write-Verbose '[Sysinternals] Decompressing archive ...'
    Remove-Item -Path "$DestPath\*" -Recurse
    Expand-Archive -Path $ZipPath -DestinationPath $DestPath
    Remove-Item -Path $ZipPath

    $Version = (Get-ChildItem $DestPath | Sort-Object -Property LastWriteTime | Select-Object -Last 1).LastWriteTime.ToString('yyyyMMdd')
    Write-Verbose "[Sysinternals] Installed version $Version."

    return $Version
}
