# See the help for Set-StrictMode for the full details on what this enables.
Set-StrictMode -Version 2.0

Function Get-VitalInformation {
    <#
        .SYNOPSIS
        Retrieves common system information and inventory

        .DESCRIPTION
        See the help for each parameter for the specifics of each retrieval task.

        If no parameters are provided then all tasks are run (provided any dependencies are met).

        .PARAMETER ComponentStoreAnalysis
        Performs a component store analysis to determine current statistics and reclaimable space.

        This parameter requires administrator privileges.

        .PARAMETER ComputerInfo
        Retrieves baseline system hardware and operating system information.

        This parameter requires Windows PowerShell 5.1 or newer.

        .PARAMETER CrashDumps
        Checks for any kernel or service account crash dumps.

        .PARAMETER DevicesNotPresent
        Retrieves any PnP devices which are not present.

        Devices which are not present are those with an "Unknown" state.

        This parameter requires Windows 10, Windows Server 2016, or newer.

        .PARAMETER DevicesWithBadStatus
        Retrieves any PnP devices with a bad status.

        A bad status corresponds to any device in an "Error" or "Degraded" state.

        This parameter requires Windows 10, Windows Server 2016, or newer.

        .PARAMETER EnvironmentVariables
        Parameter description

        .PARAMETER HypervisorInfo
        Attempts to detect if the system is running under a hypervisor.

        Currently we only detect Microsoft Hyper-V and VMware hypervisors.

        .PARAMETER InstalledFeatures
        Retrieves information on installed Windows features.

        This parameter requires a Window Server operating system.

        .PARAMETER InstalledPrograms
        Retrieves information on installed programs.

        Only programs installed system-wide are retrieved.

        .PARAMETER StorageVolumes
        Retrieves information on fixed storage volumes.

        .PARAMETER SysinternalsSuite
        Retrieves the version of the installed Sysinternals Suite if any.

        The version is retrieved from the Version.txt file created by Invoke-VitalMaintenance.

        The location where we check if the utilities are installed depends on the OS architecture:
        - 32-bit: The "Sysinternals" folder in the "Program Files" directory
        - 64-bit: The "Sysinternals" folder in the "Program Files (x86)" directory

        .PARAMETER WindowsUpdates
        Scans for any available Windows updates.

        Updates from Microsoft Update are also included if opted-in via the Windows Update configuration.

        This parameter requires the PSWindowsUpdate module.

        .EXAMPLE
        Get-VitalInformation -StorageVolumes -InstalledPrograms

        Only retrieves information on storage volumes and installed programs.

        .NOTES
        Selected inventory information is retrieved in the following order:
        - ComputerInfo
        - HypervisorInfo
        - DevicesWithBadStatus
        - DevicesNotPresent
        - StorageVolumes
        - CrashDumps
        - ComponentStoreAnalysis
        - InstalledFeatures
        - InstalledPrograms
        - EnvironmentVariables
        - WindowsUpdates
        - SysinternalsSuite

        .LINK
        https://github.com/ralish/PSWinVitals
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(ParameterSetName='Custom')]
        [Switch]$ComponentStoreAnalysis,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$ComputerInfo,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$CrashDumps,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$DevicesNotPresent,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$DevicesWithBadStatus,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$EnvironmentVariables,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$HypervisorInfo,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$InstalledFeatures,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$InstalledPrograms,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$StorageVolumes,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$SysinternalsSuite,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$WindowsUpdates
    )

    if ($PSCmdlet.ParameterSetName -eq 'Default') {
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

    $VitalInformation = [PSCustomObject]@{
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
            $VitalInformation.ComputerInfo = Get-ComputerInfo
        } else {
            Write-Warning -Message 'Unable to retrieve computer info as Get-ComputerInfo cmdlet not available.'
            $VitalInformation.ComputerInfo = $false
        }
    }

    if ($HypervisorInfo) {
        Write-Host -ForegroundColor Green -Object 'Retrieving hypervisor info ...'
        $VitalInformation.HypervisorInfo = Get-HypervisorInfo
    }

    if ($DevicesWithBadStatus) {
        if (Get-Module -Name PnpDevice -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving problem devices ...'
            $VitalInformation.DevicesWithBadStatus = Get-PnpDevice | Where-Object { $_.Status -in ('Degraded', 'Error') }
        } else {
            Write-Warning -Message 'Unable to retrieve problem devices as PnpDevice module not available.'
            $VitalInformation.DevicesWithBadStatus = $false
        }
    }

    if ($DevicesNotPresent) {
        if (Get-Module -Name PnpDevice -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving not present devices ...'
            $VitalInformation.DevicesNotPresent = Get-PnpDevice | Where-Object { $_.Status -eq 'Unknown' }
        } else {
            Write-Warning -Message 'Unable to retrieve not present devices as PnpDevice module not available.'
            $VitalInformation.DevicesNotPresent = $false
        }
    }

    if ($StorageVolumes) {
        Write-Host -ForegroundColor Green -Object 'Retrieving storage volumes summary ...'
        $VitalInformation.StorageVolumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
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

        $VitalInformation.CrashDumps = $CrashDumps
    }

    if ($ComponentStoreAnalysis) {
        Write-Host -ForegroundColor Green -Object 'Running component store analysis ...'
        $VitalInformation.ComponentStoreAnalysis = Invoke-DISM -Operation AnalyzeComponentStore
    }

    if ($InstalledFeatures) {
        if (Get-Module -Name ServerManager -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving installed features ...'
            $VitalInformation.InstalledFeatures = Get-WindowsFeature | Where-Object { $_.Installed }
        } else {
            Write-Warning -Message 'Unable to retrieve installed features as ServerManager module not available.'
            $VitalInformation.InstalledFeatures = $false
        }
    }

    if ($InstalledPrograms) {
        Write-Host -ForegroundColor Green -Object 'Retrieving installed programs ...'
        $VitalInformation.InstalledPrograms = Get-InstalledPrograms
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

        $VitalInformation.EnvironmentVariables = $EnvironmentVariables
    }

    if ($WindowsUpdates) {
        if (Get-Module -Name PSWindowsUpdate -ListAvailable) {
            Write-Host -ForegroundColor Green -Object 'Retrieving available Windows updates ...'
            $VitalInformation.WindowsUpdates = Get-WUList
        } else {
            Write-Warning -Message 'Unable to retrieve available Windows updates as PSWindowsUpdate module not available.'
            $VitalInformation.WindowsUpdates = $false
        }
    }

    if ($SysinternalsSuite) {
        if (Test-IsWindows64bit) {
            $InstallDir = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Sysinternals'
        } else {
            $InstallDir = Join-Path -Path $env:ProgramFiles -ChildPath 'Sysinternals'
        }

        if (Test-Path -Path $InstallDir -PathType Container) {
            $Sysinternals = [PSCustomObject]@{
                Path = $null
                Version = $null
                Updated = $false
            }
            $Sysinternals.Path = $InstallDir

            Write-Host -ForegroundColor Green -Object 'Retrieving Sysinternals Suite version ...'
            $VersionFile = Join-Path -Path $InstallDir -ChildPath 'Version.txt'
            if (Test-Path -Path $VersionFile -PathType Leaf) {
                $Sysinternals.Version = Get-Content -Path $VersionFile
            } else {
                Write-Warning -Message 'Unable to retrieve Sysinternals Suite version as version file is not present.'
                $Sysinternals.Version = 'Unknown'
            }

            $VitalInformation.SysinternalsSuite = $Sysinternals
        } else {
            Write-Warning -Message 'Unable to retrieve Sysinternals Suite version as it does not appear to be installed.'
            $VitalInformation.SysinternalsSuite = $false
        }
    }

    return $VitalInformation
}

Function Invoke-VitalChecks {
    <#
        .SYNOPSIS
        Performs several common system health checks

        .DESCRIPTION
        See the help for each parameter for the specifics of each health check.

        If no parameters are provided then all checks are run.

        .PARAMETER ComponentStoreScan
        Scans the component store and repairs any corruption.

        If the -VerifyOnly parameter is specified then no repairs will be performed.

        This parameter requires administrator privileges.

        .PARAMETER FileSystemScans
        Scans all non-removable storage volumes with supported file systems and repairs any corruption

        If the -VerifyOnly parameter is specified then no repairs will be performed.

        This parameter requires administrator privileges.

        .PARAMETER SystemFileChecker
        Scans system files and repairs any corruption.

        If the -VerifyOnoly parameter is specified then no repairs will be performed.

        This parameter requires administrator privileges.

        .PARAMETER VerifyOnly
        Modifies the behaviour of health checks to not repair any issues.

        .EXAMPLE
        Invoke-VitalChecks -FileSystemScans -VerifyOnly

        Only runs file system scans without performing any repairs.

        .NOTES
        Selected health checks are run in the following order:
        - FileSystemScans
        - SystemFileChecker
        - ComponentStoreScan

        .LINK
        https://github.com/ralish/PSWinVitals
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(ParameterSetName='Custom')]
        [Switch]$ComponentStoreScan,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$FileSystemScans,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$SystemFileChecker,

        [Switch]$VerifyOnly
    )

    if ($PSCmdlet.ParameterSetName -eq 'Default') {
        $ComponentStoreScan = $true
        $FileSystemScans = $true
        $SystemFileChecker = $true
    }

    if (!(Test-IsAdministrator)) {
        throw 'You must have administrator privileges to perform system health checks.'
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
    <#
        .SYNOPSIS
        Performs several common system maintenance tasks

        .DESCRIPTION
        See the help for each parameter for the specifics of each maintenance task.

        If no parameters are provided then all tasks are run (provided any dependencies are met).

        .PARAMETER ComponentStoreCleanup
        Performs a component store clean-up to remove obsolete Windows updates.

        This parameter requires administrator privileges.

        .PARAMETER ClearInternetExplorerCache
        Clears all cached Internet Explorer data for the user.

        .PARAMETER DeleteErrorReports
        Deletes all error reports (queued & archived) for the system and user.

        This parameter requires administrator privileges.

        .PARAMETER DeleteTemporaryFiles
        Recursively deletes all data in the following locations:
        - The "TEMP" environment variable path for the system
        - The "TEMP" environment variable path for the user

        This parameter requires administrator privileges.

        .PARAMETER EmptyRecycleBin
        Empties the Recycle Bin for the user.

        This parameter requires Windows 10, Windows Server 2016, or newer.

        .PARAMETER PowerShellHelp
        Updates PowerShell help for all modules.

        This parameter requires administrator privileges.

        .PARAMETER SysinternalsSuite
        Downloads and installs the latest Sysinternals Suite.

        The installation process itself consists of the following steps:
        - Download the latest Sysinternals Suite archive from download.sysinternals.com
        - Determine the version based off the date of the most recently modified file in the archive
        - If the downloaded version is newer than the installed version (if any is present) then:
        | - Remove any existing files in the installation directory and decompress the downloaded archive
        | - Write a Version.txt file in the installation directory with earlier determined version date
        - Add the installation directory to the system path environment variable if it's not already present

        The location where the utilities will be installed depends on the OS architecture:
        - 32-bit: The "Sysinternals" folder in the "Program Files" directory
        - 64-bit: The "Sysinternals" folder in the "Program Files (x86)" directory

        This parameter requires administrator privileges.

        .PARAMETER WindowsUpdates
        Downloads and installs all available Windows updates.

        Updates from Microsoft Update are also included if opted-in via the Windows Update configuration.

        This parameter requires administrator privileges and the PSWindowsUpdate module.

        .EXAMPLE
        Invoke-VitalMaintenance -WindowsUpdates -SysinternalsSuite

        Only install available Windows updates and the latest Sysinternals utilities.

        .NOTES
        Selected maintenance tasks are run in the following order:
        - WindowsUpdates
        - ComponentStoreCleanup
        - PowerShellHelp
        - SysinternalsSuite
        - ClearInternetExplorerCache
        - DeleteErrorReports
        - DeleteTemporaryFiles
        - EmptyRecycleBin

        .LINK
        https://github.com/ralish/PSWinVitals
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(ParameterSetName='Custom')]
        [Switch]$ComponentStoreCleanup,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$ClearInternetExplorerCache,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$DeleteErrorReports,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$DeleteTemporaryFiles,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$EmptyRecycleBin,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$PowerShellHelp,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$SysinternalsSuite,

        [Parameter(ParameterSetName='Custom')]
        [Switch]$WindowsUpdates
    )

    if ($PSCmdlet.ParameterSetName -eq 'Default') {
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
            Start-Process -FilePath $RunDll32Path -ArgumentList @('inetcpl.cpl,ClearMyTracksByProcess', '9FF') -Wait
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
        Remove-Item -Path "$env:TEMP\*" -Recurse -ErrorAction Ignore

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
    [CmdletBinding()]
    Param()

    $LogPrefix = 'HypervisorInfo'
    $HypervisorInfo = [PSCustomObject]@{
        Vendor = $null
        Hypervisor = $null
        ToolsVersion = $null
    }

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $Manufacturer = $ComputerSystem.Manufacturer
    $Model = $ComputerSystem.Model

    # Useful: http://git.annexia.org/?p=virt-what.git;a=blob_plain;f=virt-what.in;hb=HEAD
    if ($Manufacturer -eq 'Microsoft Corporation' -and $Model -eq 'Virtual Machine') {
        $HypervisorInfo.Vendor = 'Microsoft'
        $HypervisorInfo.Hypervisor = 'Hyper-V'

        $IntegrationServicesVersion = $false
        $VMInfoRegPath = 'HKLM:\Software\Microsoft\Virtual Machine\Auto'
        if (Test-Path -Path $VMInfoRegPath -PathType Container) {
            $VMInfo = Get-ItemProperty -Path $VMInfoRegPath
            if ($VMInfo.PSObject.Properties['IntegrationServicesVersion']) {
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

        # Skip any program which doesn't define a display name
        if ($Program.PSObject.Properties['DisplayName']) {
            # Ensure the program either:
            # - Has an uninstall command
            # - Is marked as non-removable
            if (!($Program.PSObject.Properties['UninstallString'] -or ($Program.PSObject.Properties['NoRemove'] -and $Program.NoRemove -eq 1))) {
                continue
            }

            # Skip any program which defines a parent program
            if ($Program.PSObject.Properties['ParentKeyName'] -or $Program.PSObject.Properties['ParentDisplayName']) {
                continue
            }

            # Skip any program marked as a system component
            if ($Program.PSObject.Properties['SystemComponent'] -and $Program.SystemComponent -eq 1) {
                continue
            }

            # Skip any program which defines a release type
            if ($Program.PSObject.Properties['ReleaseType']) {
                continue
            }

            $InstalledProgram = [PSCustomObject]@{
                Name = $Program.DisplayName
                Publisher = $null
                InstallDate = $null
                EstimatedSize = $null
                Version = $null
                Location = $null
                Uninstall = $null
            }

            if ($Program.PSObject.Properties['Publisher']) {
                $InstalledProgram.Publisher = $Program.Publisher
            }

            if ($Program.PSObject.Properties['InstallDate']) {
                $InstalledProgram.InstallDate = $Program.InstallDate
            }

            if ($Program.PSObject.Properties['EstimatedSize']) {
                $InstalledProgram.EstimatedSize = $Program.EstimatedSize
            }

            if ($Program.PSObject.Properties['DisplayVersion']) {
                $InstalledProgram.Version = $Program.DisplayVersion
            }

            if ($Program.PSObject.Properties['InstallLocation']) {
                $InstalledProgram.Location = $Program.InstallLocation
            }

            if ($Program.PSObject.Properties['UninstallString']) {
                $InstalledProgram.Uninstall = $Program.UninstallString
            }

            $InstalledPrograms += $InstalledProgram
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

        if ($CrashControl.PSObject.Properties['DumpFile']) {
            $DumpFile = $CrashControl.DumpFile
        } else {
            $DumpFile = Join-Path -Path $env:SystemRoot -ChildPath 'MEMORY.DMP'
            Write-Warning -Message ("[{0}] The DumpFile value doesn't exist in CrashControl so we're guessing the location." -f $LogPrefix)
        }

        if ($CrashControl.PSObject.Properties['MinidumpDir']) {
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
            0 { continue }
            2 { Write-Warning -Message ('[{0}] Volume requires cleanup: {1}' -f $LogPrefix, $VolumePath) }
            3 { Write-Warning -Message ('[{0}] Volume contains errors: {1}' -f $LogPrefix, $VolumePath) }
            default { Write-Error -Message ('[{0}] Unexpected exit code: {1}' -f $LogPrefix, $CHKDSK.ExitCode) }
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
        0 { continue }
        -2146498554 { Write-Warning -Message ('[{0}] The operation could not be completed due to pending operations.' -f $LogPrefix, $DISM.ExitCode) }
        default { Write-Error -Message ('[{0}] Returned non-zero exit code: {1}' -f $LogPrefix, $DISM.ExitCode) }
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
    # SFC output is UTF-16 in contrast to most built-in Windows console applications? We're probably
    # using ASCII (or similar), so if we don't change this, the text output will be somewhat broken.
    $DefaultOutputEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [Text.Encoding]::Unicode
    if ($Operation -eq 'Scan') {
        $SFC.Output = & $SfcPath /SCANNOW
    } else {
        $SFC.Output = & $SfcPath /VERIFYONLY
    }
    $SFC.ExitCode = $LASTEXITCODE
    [Console]::OutputEncoding = $DefaultOutputEncoding

    switch ($SFC.ExitCode) {
        0 { continue }
        default { Write-Error -Message ('[{0}] Returned non-zero exit code: {1}' -f $LogPrefix, $SFC.ExitCode) }
    }

    return $SFC
}

Function Update-Sysinternals {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
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

    $ExistingVersion = $false
    $VersionFile = Join-Path -Path $InstallDir -ChildPath 'Version.txt'
    if (Test-Path -Path $VersionFile -PathType Leaf) {
        $ExistingVersion = Get-Content -Path $VersionFile
    }

    Write-Verbose -Message ('[{0}] Downloading latest version from: {1}' -f $LogPrefix, $DownloadUrl)
    $null = New-Item -Path $DownloadDir -ItemType Directory -ErrorAction Ignore
    $WebClient = New-Object -TypeName Net.WebClient
    try {
        $WebClient.DownloadFile($DownloadUrl, $DownloadPath)
    } catch {
        # Return immediately with the error message if the download fails
        return $_.Exception.Message
    }

    Write-Verbose -Message ('[{0}] Determining downloaded version ...' -f $LogPrefix)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [IO.Compression.ZipFile]::OpenRead($DownloadPath)
    $DownloadedVersion = ($Archive.Entries.LastWriteTime | Sort-Object | Select-Object -Last 1).ToString('yyyyMMdd')
    $Archive.Dispose()

    if (!$ExistingVersion -or ($DownloadedVersion -gt $ExistingVersion)) {
        Write-Verbose -Message ('[{0}] Extracting archive to: {1}' -f $LogPrefix, $InstallDir)
        Remove-Item -Path $InstallDir -Recurse -ErrorAction Ignore
        Expand-ZipFile -FilePath $DownloadPath -DestinationPath $InstallDir
        Set-Content -Path $VersionFile -Value $DownloadedVersion
        Remove-Item -Path $DownloadPath

        $Sysinternals.Version = $DownloadedVersion
        $Sysinternals.Updated = $true
    } elseif ($DownloadedVersion -eq $ExistingVersion) {
        Write-Verbose -Message ('[{0}] Not updating as existing version is latest: {1}' -f $LogPrefix, $ExistingVersion)
        $Sysinternals.Version = $ExistingVersion
    } else {
        Write-Warning -Message ('[{0}] Installed version newer than downloaded version: {1}' -f $LogPrefix, $ExistingVersion)
        $Sysinternals.Version = $ExistingVersion
    }

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
    [OutputType([Boolean])]
    Param()

    $User = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($User.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true
    }
    return $false
}

Function Test-IsWindows64bit {
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param()

    if ((Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        return $true
    }
    return $false
}
