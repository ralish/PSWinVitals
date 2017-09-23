Function Get-VitalInformation {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param(
        [Parameter(ParameterSetName='Statistics')]
        [Switch]$ComponentStoreAnalysis,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$ComputerInfo,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$CrashDumps,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$DevicesNotPresent,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$DevicesWithBadStatus,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$EnvironmentVariables,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$HypervisorInfo,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$InstalledFeatures,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$InstalledPrograms,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$StorageVolumes,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$SysinternalsSuite,

        [Parameter(ParameterSetName='Statistics')]
        [Switch]$WindowsUpdates
    )

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ComponentStoreAnalysis = $true
        $ComputerInfo = $true
        $CrashDumps = $true
        $DevicesNotPresent = $true
        $DevicesWithBadStatus = $true
        $EnvironmentVariables = $true
        $HypervisorInfo = $true
        $InstalledFeatures = $true
        $InstalledPrograms = $true
        $StorageVolumes = $true
        $SysinternalsSuite = $true
        $WindowsUpdates = $true
    }

    if ($ComponentStoreAnalysis) {
        if (!(Test-IsAdministrator)) {
            throw 'You must have administrator privileges to analyse the component store.'
        }
    }

    $VitalStatistics = [PSCustomObject]@{
        ComponentStoreAnalysis = $null
        ComputerInfo = $null
        CrashDumps = $null
        DevicesNotPresent = $null
        DevicesWithBadStatus = $null
        EnvironmentVariables = $null
        HypervisorInfo = $null
        InstalledFeatures = $null
        InstalledPrograms = $null
        StorageVolumes = $null
        SysinternalsSuite = $null
        WindowsUpdates = $null
    }

    if ($ComputerInfo) {
        if (Get-Command -Name Get-ComputerInfo -ErrorAction Ignore) {
            Write-Host -ForegroundColor Green -Object 'Retrieving computer info ...'
            $VitalStatistics.ComputerInfo = Get-ComputerInfo
        } else {
            Write-Warning -Message 'Unable to retrieve computer info as Get-ComputerInfo cmdlet not available.'
            $VitalStatistics.ComputerInfo = $false
        }
    }

    if ($HypervisorInfo) {
        Write-Host -ForegroundColor Green -Object 'Retrieving hypervisor info ...'
        $VitalStatistics.HypervisorInfo = Get-HypervisorInfo
    }

    if ($DevicesWithBadStatus) {
        if (Get-Module -Name PnpDevice -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving problem devices ...'
            $VitalStatistics.DevicesWithBadStatus = Get-PnpDevice | Where-Object { $_.Status -in ('Degraded', 'Error') }
        } else {
            Write-Warning -Message 'Unable to retrieve problem devices as PnpDevice module not available.'
            $VitalStatistics.DevicesWithBadStatus = $false
        }
    }

    if ($DevicesNotPresent) {
        if (Get-Module -Name PnpDevice -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving not present devices ...'
            $VitalStatistics.DevicesNotPresent = Get-PnpDevice | Where-Object { $_.Status -eq 'Unknown' }
        } else {
            Write-Warning -Message 'Unable to retrieve not present devices as PnpDevice module not available.'
            $VitalStatistics.DevicesNotPresent = $false
        }
    }

    if ($StorageVolumes) {
        Write-Host -ForegroundColor Green -Object 'Retrieving storage volumes summary ...'
        $VitalStatistics.StorageVolumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
    }

    if ($CrashDumps) {
        [PSCustomObject]$CrashDumps = [PSCustomObject]@{
            Kernel = $null
            Service = $null
        }

        Write-Host -ForegroundColor Green -Object 'Retrieving kernel crash dumps ...'
        $CrashDumps.Kernel = Get-KernelCrashDumps

        Write-Host -ForegroundColor Green -Object 'Retrieving service crash dumps ...'
        $CrashDumps.Service = Get-ServiceCrashDumps

        $VitalStatistics.CrashDumps = $CrashDumps
    }

    if ($ComponentStoreAnalysis) {
        Write-Host -ForegroundColor Green -Object 'Running component store analysis ...'
        $VitalStatistics.ComponentStoreAnalysis = Invoke-DISM -Operation AnalyzeComponentStore
    }

    if ($InstalledFeatures) {
        if (Get-Module -Name ServerManager -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving installed features ...'
            $VitalStatistics.InstalledFeatures = Get-WindowsFeature | Where-Object { $_.Installed }
        } else {
            Write-Warning -Message 'Unable to retrieve installed features as ServerManager module not available.'
            $VitalStatistics.InstalledFeatures = $false
        }
    }

    if ($InstalledPrograms) {
        Write-Host -ForegroundColor Green -Object 'Retrieving installed programs ...'
        $VitalStatistics.InstalledPrograms = Get-InstalledPrograms
    }

    if ($EnvironmentVariables) {
        [PSCustomObject]$EnvironmentVariables = [PSCustomObject]@{
            Machine = $null
            User = $null
        }

        Write-Host -ForegroundColor Green -Object 'Retrieving system environment variables ...'
        $EnvironmentVariables.Machine = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)

        Write-Host -ForegroundColor Green -Object 'Retrieving user environment variables ...'
        $EnvironmentVariables.User = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)

        $VitalStatistics.EnvironmentVariables = $EnvironmentVariables
    }

    if ($WindowsUpdates) {
        if (Get-Module -Name PSWindowsUpdate -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving available Windows updates ...'
            $VitalStatistics.WindowsUpdates = Get-WUList
        } else {
            Write-Warning -Message 'Unable to retrieve available Windows updates as PSWindowsUpdate module not available.'
            $VitalStatistics.WindowsUpdates = $false
        }
    }

    if ($SysinternalsSuite) {
        if (Test-IsWindows64bit) {
            $InstallDir = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Sysinternals'
        } else {
            $InstallDir = Join-Path -Path $env:ProgramFiles -ChildPath 'Sysinternals'
        }

        if (Test-Path -Path $InstallDir -PathType Container) {
            Write-Host -ForegroundColor Green -Object 'Retrieving Sysinternals Suite version ...'
            $Sysinternals = [PSCustomObject]@{
                Path = $null
                Version = $null
                Updated = $false
            }

            $Sysinternals.Path = $InstallDir
            $Sysinternals.Version = (Get-Item -Path $InstallDir).CreationTime.ToString('yyyyMMdd')
            $VitalStatistics.SysinternalsSuite = $Sysinternals
        } else {
            Write-Warning -Message 'Unable to retrieve Sysinternals Suite version as it does not appear to be installed.'
            $VitalStatistics.SysinternalsSuite = $false
        }
    }

    return $VitalStatistics
}

Function Invoke-VitalChecks {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param(
        [Parameter(ParameterSetName='Checks')]
        [Switch]$ComponentStoreScan,

        [Parameter(ParameterSetName='Checks')]
        [Switch]$FileSystemScans,

        [Parameter(ParameterSetName='Checks')]
        [Switch]$SystemFileChecker,

        [Switch]$VerifyOnly
    )

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ComponentStoreScan = $true
        $FileSystemScans = $true
        $SystemFileChecker = $true
    }

    if (!(Test-IsAdministrator)) {
        throw 'You must have administrator privileges to perform system checks.'
    }

    $VitalChecks = [PSCustomObject]@{
        ComponentStoreScan = $null
        FileSystemScans = $null
        SystemFileChecker = $null
    }

    if ($FileSystemScans) {
        Write-Host -ForegroundColor Green -Object 'Running file system scans ...'
        if ($VerifyOnly) {
            $VitalChecks.FileSystemScans = Invoke-CHKDSK -Operation Verify
        } else {
            $VitalChecks.FileSystemScans = Invoke-CHKDSK -Operation Scan
        }
    }

    if ($SystemFileChecker) {
        Write-Host -ForegroundColor Green -Object 'Running System File Checker ...'
        if ($VerifyOnly) {
            $VitalChecks.SystemFileChecker = Invoke-SFC -Operation Verify
        } else {
            $VitalChecks.SystemFileChecker = Invoke-SFC -Operation Scan
        }
    }

    if ($ComponentStoreScan) {
        Write-Host -ForegroundColor Green -Object 'Running component store scan ...'
        if ($VerifyOnly) {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation ScanHealth
        } else {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation RestoreHealth
        }
    }

    return $VitalChecks
}

Function Invoke-VitalMaintenance {
    [CmdletBinding(DefaultParameterSetName='All')]
    Param(
        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$ComponentStoreCleanup,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$ClearInternetExplorerCache,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$DeleteErrorReports,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$DeleteTemporaryFiles,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$EmptyRecycleBin,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$PowerShellHelp,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$SysinternalsSuite,

        [Parameter(ParameterSetName='Maintenance')]
        [Switch]$WindowsUpdates
    )

    if ($PSCmdlet.ParameterSetName -eq 'All') {
        $ClearInternetExplorerCache = $true
        $ComponentStoreCleanup = $true
        $DeleteErrorReports = $true
        $DeleteTemporaryFiles = $true
        $EmptyRecycleBin = $true
        $PowerShellHelp = $true
        $SysinternalsSuite = $true
        $WindowsUpdates = $true
    }

    if (!(Test-IsAdministrator)) {
        throw 'You must have administrator privileges to perform system maintenance.'
    }

    $VitalMaintenance = [PSCustomObject]@{
        ClearInternetExplorerCache = $null
        ComponentStoreCleanup = $null
        DeleteErrorReports = $null
        DeleteTemporaryFiles = $null
        EmptyRecycleBin = $null
        PowerShellHelp = $null
        SysinternalsSuite = $null
        WindowsUpdates = $null
    }

    if ($WindowsUpdates) {
        if (Get-Module -Name PSWindowsUpdate -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Installing available Windows updates ...'
            $VitalMaintenance.WindowsUpdates = Get-WUInstall -AcceptAll -IgnoreReboot
        } else {
            Write-Warning -Message 'Unable to install available Windows updates as PSWindowsUpdate module not available.'
            $VitalMaintenance.WindowsUpdates = $false
        }
    }

    if ($ComponentStoreCleanup) {
        Write-Host -ForegroundColor Green -Object 'Running component store clean-up ...'
        $VitalMaintenance.ComponentStoreCleanup = Invoke-DISM -Operation StartComponentCleanup
    }

    if ($PowerShellHelp) {
        Write-Host -ForegroundColor Green -Object 'Updating PowerShell help ...'
        try {
            Update-Help -Force -ErrorAction Stop
            $VitalMaintenance.PowerShellHelp = $true
        } catch {
            # Often we'll fail to update help data for a few modules because they haven't defined
            # the HelpInfoUri key in their manifest. There's nothing that can be done to fix this.
            $VitalMaintenance.PowerShellHelp = $_.Exception.Message
        }
    }

    if ($SysinternalsSuite) {
        Write-Host -ForegroundColor Green -Object 'Updating Sysinternals Suite ...'
        $VitalMaintenance.SysinternalsSuite = Update-Sysinternals
    }

    if ($ClearInternetExplorerCache) {
        if (Get-Command -Name inetcpl.cpl -ErrorAction Ignore) {
            Write-Host -ForegroundColor Green -Object 'Clearing Internet Explorer cache ...'
            # More details on the bitmask here: https://github.com/SeleniumHQ/selenium/blob/master/cpp/iedriver/BrowserFactory.cpp
            $RunDll32Path = Join-Path -Path $env:SystemRoot -ChildPath 'System32\rundll32.exe'
            & $RunDll32Path inetcpl.cpl,ClearMyTracksByProcess 9FF
            $VitalMaintenance.ClearInternetExplorerCache = $true
        } else {
            Write-Warning -Message 'Unable to clear Internet Explorer cache as Control Panel applet not available.'
            $VitalMaintenance.ClearInternetExplorerCache = $false
        }
    }

    if ($DeleteErrorReports) {
        Write-Host -ForegroundColor Green -Object 'Deleting system error reports ...'
        $SystemReports = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\WER'
        $SystemQueue = Join-Path -Path $SystemReports -ChildPath 'ReportQueue'
        $SystemArchive = Join-Path -Path $SystemReports -ChildPath 'ReportArchive'
        foreach ($Path in @($SystemQueue, $SystemArchive)) {
            if (Test-Path -Path $Path -PathType Container) {
                Remove-Item -Path "$Path\*" -Recurse -ErrorAction Ignore
            }
        }

        Write-Host -ForegroundColor Green -Object ('Deleting {0} error reports ...' -f $env:USERNAME)
        $UserReports = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\WER'
        $UserQueue = Join-Path -Path $UserReports -ChildPath 'ReportQueue'
        $UserArchive = Join-Path -Path $UserReports -ChildPath 'ReportArchive'
        foreach ($Path in @($UserQueue, $UserArchive)) {
            if (Test-Path -Path $Path -PathType Container) {
                Remove-Item -Path "$Path\*" -Recurse -ErrorAction Ignore
            }
        }

        $VitalMaintenance.DeleteErrorReports = $true
    }

    if ($DeleteTemporaryFiles) {
        Write-Host -ForegroundColor Green -Object 'Deleting system temporary files ...'
        $SystemTemp = [Environment]::GetEnvironmentVariable('Temp', [EnvironmentVariableTarget]::Machine)
        Remove-Item -Path "$SystemTemp\*" -Recurse -ErrorAction Ignore

        Write-Host -ForegroundColor Green -Object ('Deleting {0} temporary files ...' -f $env:USERNAME)
        $UserTemp = [Environment]::GetEnvironmentVariable('Temp', [EnvironmentVariableTarget]::User)
        Remove-Item -Path "$UserTemp\*" -Recurse -ErrorAction Ignore

        $VitalMaintenance.DeleteTemporaryFiles = $true
    }

    if ($EmptyRecycleBin) {
        if (Get-Command -Name Clear-RecycleBin -ErrorAction Ignore) {
            Write-Host -ForegroundColor Green -Object 'Emptying Recycle Bin ...'
            try {
                Clear-RecycleBin -Force -ErrorAction Stop
                $VitalMaintenance.EmptyRecycleBin = $true
            } catch [ComponentModel.Win32Exception] {
                # Sometimes clearing the Recycle Bin fails with an exception which seems to indicate
                # the Recycle Bin folder doesn't exist. If that happens we only get a generic E_FAIL
                # exception, so checking the actual exception message seems to be the best method.
                if ($_.Exception.Message -eq 'The system cannot find the path specified') {
                    $VitalMaintenance.EmptyRecycleBin = $true
                } else {
                    $VitalMaintenance.EmptyRecycleBin = $_.Exception.Message
                }
            }
        } else {
            Write-Warning -Message 'Unable to empty Recycle Bin as Clear-RecycleBin cmdlet not available.'
            $VitalMaintenance.EmptyRecycleBin = $false
        }
    }

    return $VitalMaintenance
}

Function Get-HypervisorInfo {
    [CmdletBinding()]
    Param()

    $LogPrefix = 'HypervisorInfo'
    $HypervisorInfo = [PSCustomObject]@{
        Vendor = $null
        Hypervisor = $null
        ToolsVersion = $null
    }

    $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $Manufacturer = $ComputerSystem.Manufacturer
    $Model = $ComputerSystem.Model

    # Useful: http://git.annexia.org/?p=virt-what.git;a=blob_plain;f=virt-what.in;hb=HEAD
    if ($Manufacturer -eq 'Microsoft Corporation' -and $Model -eq 'Virtual Machine') {
        $HypervisorInfo.Vendor = 'Microsoft'
        $HypervisorInfo.Hypervisor = 'Hyper-V'

        $VMInfoRegPath = 'HKLM:\Software\Microsoft\Virtual Machine\Auto'
        if (Test-Path -Path $VMInfoRegPath -PathType Container) {
            $VMInfo = Get-ItemProperty -Path $VMInfoRegPath
            if ($VMInfo.IntegrationServicesVersion) {
                $IntegrationServicesVersion = $VMInfo.IntegrationServicesVersion
            }
        }

        if ($IntegrationServicesVersion) {
            $HypervisorInfo.ToolsVersion = $VMinfo.IntegrationServicesVersion
        } else {
            Write-Warning -Message ('[{0}] Detected Microsoft Hyper-V but unable to determine Integration Services version.' -f $LogPrefix)
        }
    } elseif ($Manufacturer -eq 'VMware, Inc.' -and $Model -match '^VMware') {
        $HypervisorInfo.Vendor = 'VMware'
        $HypervisorInfo.Hypervisor = 'Unknown'

        $VMwareToolboxCmd = Join-Path -Path $env:ProgramFiles -ChildPath 'VMware\VMware Tools\VMwareToolboxCmd.exe'
        if (Test-Path -Path $VMwareToolboxCmd -PathType Leaf) {
            $HypervisorInfo.ToolsVersion = & $VMwareToolboxCmd -v
        } else {
            Write-Warning -Message ('[{0}] Detected a VMware hypervisor but unable to determine VMware Tools version.' -f $LogPrefix)
        }
    } else {
        Write-Verbose -Message ('[{0}] Either not running in a hypervisor or hypervisor not recognised.' -f $LogPrefix)
        return $false
    }

    return $HypervisorInfo
}

Function Get-InstalledPrograms {
    [CmdletBinding()]
    Param()

    $NativeRegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    $Wow6432RegPath = 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    $UninstallKeys = Get-ChildItem -Path $NativeRegPath
    if (Test-Path -Path $Wow6432RegPath -PathType Container) {
        $UninstallKeys += Get-ChildItem -Path $Wow6432RegPath
    }

    $InstalledPrograms = @()
    foreach ($UninstallKey in $UninstallKeys) {
        $Program = Get-ItemProperty -Path $UninstallKey.PSPath
        if ($Program.DisplayName -and
            !$Program.SystemComponent -and
            !$Program.ReleaseType -and
            !$Program.ParentKeyName -and
            ($Program.UninstallString -or $Program.NoRemove)) {
            $InstalledPrograms += [PSCustomObject]@{
                Name = $Program.DisplayName
                Publisher = $Program.Publisher
                InstallDate = $Program.InstallDate
                EstimatedSize = $Program.EstimatedSize
                Version = $Program.DisplayVersion
                Location = $Program.InstallLocation
                Uninstall = $Program.UninstallString
            }
        }
    }

    return $InstalledPrograms
}

Function Get-KernelCrashDumps {
    [CmdletBinding()]
    Param()

    $LogPrefix = 'KernelCrashDumps'
    $KernelCrashDumps = [PSCustomObject]@{
        MemoryDump = $null
        Minidumps = $null
    }

    $CrashControlRegPath = 'HKLM:\System\CurrentControlSet\Control\CrashControl'

    if (Test-Path -Path $CrashControlRegPath -PathType Container) {
        $CrashControl = Get-ItemProperty -Path $CrashControlRegPath

        if ($CrashControl.DumpFile) {
            $DumpFile = $CrashControl.DumpFile
        } else {
            $DumpFile = Join-Path -Path $env:SystemRoot -ChildPath 'MEMORY.DMP'
            Write-Warning -Message ("[{0}] The DumpFile value doesn't exist in CrashControl so we're guessing the location." -f $LogPrefix)
        }

        if ($CrashControl.MinidumpDir) {
            $MinidumpDir = $CrashControl.MinidumpDir
        } else {
            $DumpFile = Join-Path -Path $env:SystemRoot -ChildPath 'Minidump'
            Write-Warning -Message ("[{0}]The MinidumpDir value doesn't exist in CrashControl so we're guessing the location." -f $LogPrefix)
        }
    } else {
        Write-Warning -Message ("[{0}]The CrashControl key doesn't exist in the Registry so we're guessing dump locations." -f $LogPrefix)
    }

    if (Test-Path -Path $DumpFile -PathType Leaf) {
        $KernelCrashDumps.MemoryDump = Get-Item -Path $DumpFile
    }

    if (Test-Path -Path $MinidumpDir -PathType Container) {
        $KernelCrashDumps.Minidumps = Get-ChildItem -Path $MinidumpDir
    }

    return $KernelCrashDumps
}

Function Get-ServiceCrashDumps {
    [CmdletBinding()]
    Param()

    $LogPrefix = 'ServiceCrashDumps'
    $ServiceCrashDumps = [PSCustomObject]@{
        LocalSystem = $null
        LocalService = $null
        NetworkService = $null
    }

    $LocalSystemPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\Config\SystemProfile\AppData\Local\CrashDumps'
    $LocalServicePath = Join-Path -Path $env:SystemRoot -ChildPath 'ServiceProfiles\LocalService\AppData\Local\CrashDumps'
    $NetworkServicePath = Join-Path -Path $env:SystemRoot -ChildPath 'ServiceProfiles\NetworkService\AppData\Local\CrashDumps'

    if (Test-Path -Path $LocalSystemPath -PathType Container) {
        $ServiceCrashDumps.LocalSystem = Get-ChildItem -Path $LocalSystemPath
    } else {
        Write-Verbose -Message ("[{0}] The crash dumps path for the LocalSystem account doesn't exist." -f $LogPrefix)
    }

    if (Test-Path -Path $LocalServicePath -PathType Container) {
        $ServiceCrashDumps.LocalService = Get-ChildItem -Path $LocalServicePath
    } else {
        Write-Verbose -Message ("[{0}] The crash dumps path for the LocalService account doesn't exist." -f $LogPrefix)
    }

    if (Test-Path -Path $NetworkServicePath -PathType Container) {
        $ServiceCrashDumps.NetworkService = Get-ChildItem -Path $NetworkServicePath
    } else {
        Write-Verbose -Message ("[{0}] The crash dumps path for the NetworkService account doesn't exist." -f $LogPrefix)
    }

    return $ServiceCrashDumps
}

Function Invoke-CHKDSK {
    [CmdletBinding()]
    Param(
        [ValidateSet('Scan', 'Verify')]
        [String]$Operation = 'Scan'
    )

    # We could use the Repair-Volume cmdlet introduced in Windows 8/Server 2012, but it's just a
    # thin wrapper around CHKDSK and only exposes a small subset of its underlying functionality.
    $LogPrefix = 'CHKDSK'

    $SupportedFileSystems = @('FAT', 'FAT16', 'FAT32', 'NTFS', 'NTFS4', 'NTFS5')
    $Volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -in $SupportedFileSystems }

    [PSCustomObject[]]$Results = $null
    foreach ($Volume in $Volumes) {
        $VolumePath = $Volume.Path.TrimEnd('\')
        $CHKDSK = [PSCustomObject]@{
            Operation = $Operation
            VolumePath = $VolumePath
            Output = $null
            ExitCode = $null
        }

        Write-Verbose -Message ('[{0}] Running {1} operation on: {2}' -f $LogPrefix, $Operation.ToLower(), $VolumePath)
        $ChkDskPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\chkdsk.exe'
        if ($Operation -eq 'Scan') {
            $CHKDSK.Output += & $ChkDskPath "$VolumePath" /scan
        } else {
            $CHKDSK.Output += & $ChkDskPath "$VolumePath"
        }
        $CHKDSK.ExitCode = $LASTEXITCODE

        switch ($CHKDSK.ExitCode) {
            0           { continue }
            2           { Write-Warning -Message ('[{0}] Volume requires cleanup: {1}' -f $LogPrefix, $VolumePath) }
            3           { Write-Warning -Message ('[{0}] Volume contains errors: {1}' -f $LogPrefix, $VolumePath) }
            default     { Write-Error -Message ('[{0}] Unexpected exit code: {1}' -f $LogPrefix, $CHKDSK.ExitCode) }
        }

        $Results += $CHKDSK
    }

    return $Results
}

Function Invoke-DISM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateSet('AnalyzeComponentStore', 'RestoreHealth', 'ScanHealth', 'StartComponentCleanup')]
        [String]$Operation
    )

    # The Dism PowerShell module doesn't appear to expose the /Cleanup-Image family of parameters
    # available in the underlying Dism.exe utility, so we have to fallback to invoking it directly.
    $LogPrefix = 'DISM'
    $DISM = [PSCustomObject]@{
        Operation = $Operation
        Output = $null
        ExitCode = $null
    }

    Write-Verbose -Message ('[{0}] Running {1} operation ...' -f $LogPrefix, $Operation)
    $DismPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\dism.exe'
    $DISM.Output = & $DismPath /Online /Cleanup-Image /$Operation
    $DISM.ExitCode = $LASTEXITCODE

    switch ($DISM.ExitCode) {
        0           { continue }
        -2146498554 { Write-Warning -Message ('[{0}] The operation could not be completed due to pending operations.' -f $LogPrefix, $DISM.ExitCode) }
        default     { Write-Error -Message ('[{0}] Returned non-zero exit code: {1}' -f $LogPrefix, $DISM.ExitCode) }
    }

    return $DISM
}

Function Invoke-SFC {
    [CmdletBinding()]
    Param(
        [ValidateSet('Scan', 'Verify')]
        [String]$Operation = 'Scan'
    )

    $LogPrefix = 'SFC'
    $SFC = [PSCustomObject]@{
        Operation = $Operation
        Output = $null
        ExitCode = $null
    }

    Write-Verbose -Message ('[{0}] Running {1} operation ...' -f $LogPrefix, $Operation.ToLower())
    $SfcPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\sfc.exe'
    if ($Operation -eq 'Scan') {
        $SFC.Output = & $SfcPath /SCANNOW
    } else {
        $SFC.Output = & $SfcPath /VERIFYONLY
    }
    $SFC.ExitCode = $LASTEXITCODE

    switch ($SFC.ExitCode) {
        0           { continue }
        default     { Write-Error -Message ('[{0}] Returned non-zero exit code: {1}' -f $LogPrefix, $SFC.ExitCode) }
    }

    return $SFC
}

Function Update-Sysinternals {
    [CmdletBinding()]
    Param(
        [ValidatePattern('^http[Ss]?://.*')]
        [String]$DownloadUrl = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    )

    $LogPrefix = 'Sysinternals'
    $Sysinternals = [PSCustomObject]@{
        Path = $null
        Version = $null
        Updated = $false
    }

    $DownloadDir = $env:TEMP
    $DownloadFile = Split-Path -Path $DownloadUrl -Leaf
    $DownloadPath = Join-Path -Path $DownloadDir -ChildPath $DownloadFile

    if (Test-IsWindows64bit) {
        $InstallDir = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Sysinternals'
    } else {
        $InstallDir = Join-Path -Path $env:ProgramFiles -ChildPath 'Sysinternals'
    }
    $Sysinternals.Path = $InstallDir

    if (Test-Path -Path $InstallDir -PathType Container) {
        $ExistingVersion = (Get-Item -Path $InstallDir).CreationTime.ToString('yyyyMMdd')
    }

    Write-Verbose -Message ('[{0}] Downloading latest version from: {1}' -f $LogPrefix, $DownloadUrl)
    $null = New-Item -Path $DownloadDir -ItemType Directory -ErrorAction Ignore
    $WebClient = New-Object -TypeName Net.WebClient
    $WebClient.DownloadFile($DownloadUrl, $DownloadPath)

    Write-Verbose -Message ('[{0}] Extracting archive to: {1}' -f $LogPrefix, $InstallDir)
    Remove-Item -Path $InstallDir -Recurse -ErrorAction Ignore
    Expand-ZipFile -FilePath $DownloadPath -DestinationPath $InstallDir
    Remove-Item -Path $DownloadPath

    $SystemPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
    $RegEx = [Regex]::Escape($InstallDir)
    if (!($SystemPath -match "^;*$RegEx;" -or $SystemPath -match ";$RegEx;" -or $SystemPath -match ";$RegEx;*$")) {
        Write-Verbose -Message ('[{0}] Updating system path ...' -f $LogPrefix)
        if (!$SystemPath.EndsWith(';')) {
            $SystemPath += ';'
        }
        $SystemPath += $InstallDir
        [Environment]::SetEnvironmentVariable('Path', $SystemPath, [EnvironmentVariableTarget]::Machine)
    }

    $Sysinternals.Version = (Get-Item -Path $InstallDir).CreationTime.ToString('yyyyMMdd')
    if (!$ExistingVersion -or $Sysinternals.Version -ne $ExistingVersion) {
        $Sysinternals.Updated = $true
    }

    Write-Verbose -Message ('[{0}] Installed version: {1}' -f $LogPrefix, $Sysinternals.Version)
    return $Sysinternals
}

Function Expand-ZipFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$FilePath,

        [Parameter(Mandatory)]
        [String]$DestinationPath
    )

    # The Expand-Archive cmdlet is only available from v5.0
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Expand-Archive -Path $FilePath -DestinationPath $DestinationPath
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($FilePath, $DestinationPath)
    }
}

Function Test-IsAdministrator {
    [CmdletBinding()]
    Param()

    $User = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($User.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true
    }
    return $false
}

Function Test-IsWindows64bit {
    [CmdletBinding()]
    Param()

    if ((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        return $true
    }
    return $false
}
