# See the help for Set-StrictMode for the full details on what this enables.
Set-StrictMode -Version 2.0

Function Get-VitalInformation {
    <#
        .SYNOPSIS
        Retrieves system information and inventory

        .DESCRIPTION
        The following tasks are available:
        - ComponentStoreAnalysis
          Performs a component store analysis to determine current statistics and reclaimable space.

          This task requires administrator privileges.

        - ComputerInfo
          Retrieves baseline system hardware and operating system information.

          This task requires Windows PowerShell 5.1 or newer.

        - CrashDumps
          Checks for any kernel, service, or user crash dumps.

          This task requires administrator privileges.

        - DevicesNotPresent
          Retrieves any PnP devices which are not present.

          Devices which are not present are those with an "Unknown" state.

          This task requires Windows 10, Windows Server 2016, or newer.

        - DevicesWithBadStatus
          Retrieves any PnP devices with a bad status.

          A bad status corresponds to any device in an "Error" or "Degraded" state.

          This task requires Windows 10, Windows Server 2016, or newer.

        - EnvironmentVariables
          Retrieves environment variables for the system and current user.

        - HypervisorInfo
          Attempts to detect if the system is running under a hypervisor.

          Currently only Microsoft Hyper-V and VMware hypervisors are detected.

        - InstalledFeatures
          Retrieves information on installed Windows features.

          This task requires a Window Server operating system.

        - InstalledPrograms
          Retrieves information on installed programs.

          Only programs installed system-wide are retrieved.

        - StorageVolumes
          Retrieves information on fixed storage volumes.

          This task requires Windows 8, Windows Server 2012, or newer.

        - SysinternalsSuite
          Retrieves the version of the installed Sysinternals Suite if any.

          The version is retrieved from the Version.txt file created by Invoke-VitalMaintenance.

          The location to check if the utilities are installed depends on the OS architecture:
          * 32-bit: The "Sysinternals" folder in the "Program Files" directory
          * 64-bit: The "Sysinternals" folder in the "Program Files (x86)" directory

        - WindowsUpdates
          Scans for any available Windows updates.

          Updates from Microsoft Update are also included if opted-in via the Windows Update configuration.

          This task requires administrator privileges and the PSWindowsUpdate module.

        The default is to run all tasks.

        .PARAMETER ExcludeTasks
        Array of tasks to exclude. The default is an empty array (i.e. run all tasks).

        .PARAMETER IncludeTasks
        Array of tasks to include. At least one task must be specified.

        .PARAMETER WUParameters
        Hashtable of additional parameters to pass to Get-WindowsUpdate.

        Only used if the WindowsUpdates task is selected.

        .EXAMPLE
        Get-VitalInformation -IncludeTasks StorageVolumes, InstalledPrograms

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

        When running without administrator privileges, the handling of tasks which require administrator privileges differs by selection method:
        - ExcludeTasks (default)
          Administrator tasks which were not explicitly excluded will be automatically excluded and a warning displayed.
        - IncludeTasks
          Administrator tasks will result in the command exiting with an error.

        .LINK
        https://github.com/ralish/PSWinVitals
    #>

    [CmdletBinding(DefaultParameterSetName = 'OptOut')]
    Param(
        [Parameter(ParameterSetName = 'OptOut')]
        [ValidateSet(
            'ComponentStoreAnalysis',
            'ComputerInfo',
            'CrashDumps',
            'DevicesNotPresent',
            'DevicesWithBadStatus',
            'EnvironmentVariables',
            'HypervisorInfo',
            'InstalledFeatures',
            'InstalledPrograms',
            'StorageVolumes',
            'SysinternalsSuite',
            'WindowsUpdates'
        )]
        [String[]]$ExcludeTasks,

        [Parameter(ParameterSetName = 'OptIn', Mandatory)]
        [ValidateSet(
            'ComponentStoreAnalysis',
            'ComputerInfo',
            'CrashDumps',
            'DevicesNotPresent',
            'DevicesWithBadStatus',
            'EnvironmentVariables',
            'HypervisorInfo',
            'InstalledFeatures',
            'InstalledPrograms',
            'StorageVolumes',
            'SysinternalsSuite',
            'WindowsUpdates'
        )]
        [String[]]$IncludeTasks,

        [ValidateNotNull()]
        [Hashtable]$WUParameters = @{}
    )

    $Tasks = @{
        ComponentStoreAnalysis = $null
        ComputerInfo           = $null
        CrashDumps             = $null
        DevicesNotPresent      = $null
        DevicesWithBadStatus   = $null
        EnvironmentVariables   = $null
        HypervisorInfo         = $null
        InstalledFeatures      = $null
        InstalledPrograms      = $null
        StorageVolumes         = $null
        SysinternalsSuite      = $null
        WindowsUpdates         = $null
    }

    $TasksDone = 0
    $TasksTotal = 0

    foreach ($Task in @($Tasks.Keys)) {
        if ($PSCmdlet.ParameterSetName -eq 'OptOut') {
            if ($ExcludeTasks -contains $Task) {
                $Tasks[$Task] = $false
            } else {
                $Tasks[$Task] = $true
                $TasksTotal++
            }
        } else {
            if ($IncludeTasks -contains $Task) {
                $Tasks[$Task] = $true
                $TasksTotal++
            } else {
                $Tasks[$Task] = $false
            }
        }
    }

    if (!(Test-IsAdministrator)) {
        $AdminTasks = 'ComponentStoreAnalysis', 'CrashDumps', 'WindowsUpdates'
        $SelectedAdminTasks = New-Object -TypeName 'Collections.ArrayList'

        if ($PSCmdlet.ParameterSetName -eq 'OptOut') {
            foreach ($AdminTask in $AdminTasks) {
                if ($Tasks[$AdminTask]) {
                    $Tasks[$AdminTask] = $false
                    $null = $SelectedAdminTasks.Add($AdminTask)
                }
            }

            if ($SelectedAdminTasks.Count -gt 0) {
                Write-Warning -Message ('Skipping tasks which require administrator privileges: {0}' -f [String]::Join(', ', $SelectedAdminTasks.ToArray()))
            }
        } else {
            foreach ($AdminTask in $AdminTasks) {
                if ($Tasks[$AdminTask]) {
                    $null = $SelectedAdminTasks.Add($AdminTask)
                }
            }

            if ($SelectedAdminTasks.Count -gt 0) {
                throw 'Some selected tasks require administrator privileges: {0}' -f [String]::Join(', ', $SelectedAdminTasks.ToArray())
            }
        }
    }

    $VitalInformation = [PSCustomObject]@{
        ComponentStoreAnalysis = $null
        ComputerInfo           = $null
        CrashDumps             = $null
        DevicesNotPresent      = $null
        DevicesWithBadStatus   = $null
        EnvironmentVariables   = $null
        HypervisorInfo         = $null
        InstalledFeatures      = $null
        InstalledPrograms      = $null
        StorageVolumes         = $null
        SysinternalsSuite      = $null
        WindowsUpdates         = $null
    }
    $VitalInformation.PSObject.TypeNames.Insert(0, 'PSWinVitals.VitalInformation')

    $WriteProgressParams = @{
        Activity = 'Retrieving vital information'
    }

    if ($Tasks['ComputerInfo']) {
        if (Get-Command -Name 'Get-ComputerInfo' -ErrorAction Ignore) {
            Write-Progress @WriteProgressParams -Status 'Retrieving computer info' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $VitalInformation.ComputerInfo = Get-ComputerInfo
        } else {
            Write-Warning -Message 'Unable to retrieve computer info as Get-ComputerInfo cmdlet not available.'
            $VitalInformation.ComputerInfo = $false
        }
        $TasksDone++
    }

    if ($Tasks['HypervisorInfo']) {
        Write-Progress @WriteProgressParams -Status 'Retrieving hypervisor info' -PercentComplete ($TasksDone / $TasksTotal * 100)
        $VitalInformation.HypervisorInfo = Get-HypervisorInfo
        $TasksDone++
    }

    if ($Tasks['DevicesWithBadStatus']) {
        if (Get-Module -Name 'PnpDevice' -ListAvailable -Verbose:$false) {
            Write-Progress @WriteProgressParams -Status 'Retrieving problem devices' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $VitalInformation.DevicesWithBadStatus = @(Get-PnpDevice | Where-Object Status -In 'Degraded', 'Error')
        } else {
            Write-Warning -Message 'Unable to retrieve problem devices as PnpDevice module not available.'
            $VitalInformation.DevicesWithBadStatus = $false
        }
        $TasksDone++
    }

    if ($Tasks['DevicesNotPresent']) {
        if (Get-Module -Name 'PnpDevice' -ListAvailable -Verbose:$false) {
            Write-Progress @WriteProgressParams -Status 'Retrieving not present devices' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $VitalInformation.DevicesNotPresent = @(Get-PnpDevice | Where-Object Status -EQ 'Unknown')
        } else {
            Write-Warning -Message 'Unable to retrieve not present devices as PnpDevice module not available.'
            $VitalInformation.DevicesNotPresent = $false
        }
        $TasksDone++
    }

    if ($Tasks['StorageVolumes']) {
        if (Get-Module -Name 'Storage' -ListAvailable -Verbose:$false) {
            Write-Progress @WriteProgressParams -Status 'Retrieving storage volumes summary' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $VitalInformation.StorageVolumes = @(Get-Volume | Where-Object DriveType -EQ 'Fixed')
        } else {
            Write-Warning -Message 'Unable to retrieve storage volumes summary as Storage module not available.'
            $VitalInformation.StorageVolumes = $false
        }
        $TasksDone++
    }

    if ($Tasks['CrashDumps']) {
        Write-Progress @WriteProgressParams -Status 'Retrieving crash dumps' -PercentComplete ($TasksDone / $TasksTotal * 100)

        $CrashDumps = [PSCustomObject]@{
            Kernel  = $null
            Service = $null
            User    = $null
        }
        $CrashDumps.PSObject.TypeNames.Insert(0, 'PSWinVitals.CrashDumps')

        $CrashDumps.Kernel = Get-KernelCrashDumps
        $CrashDumps.Service = Get-ServiceCrashDumps
        $CrashDumps.User = Get-UserCrashDumps

        $VitalInformation.CrashDumps = $CrashDumps
        $TasksDone++
    }

    if ($Tasks['ComponentStoreAnalysis']) {
        Write-Progress @WriteProgressParams -Status 'Running component store analysis' -PercentComplete ($TasksDone / $TasksTotal * 100)
        $VitalInformation.ComponentStoreAnalysis = Invoke-DISM -Operation AnalyzeComponentStore
        $TasksDone++
    }

    if ($Tasks['InstalledFeatures']) {
        if ((Get-WindowsProductType) -gt 1) {
            if (Get-Module -Name 'ServerManager' -ListAvailable -Verbose:$false) {
                Write-Progress @WriteProgressParams -Status 'Retrieving installed features' -PercentComplete ($TasksDone / $TasksTotal * 100)
                $VitalInformation.InstalledFeatures = @(Get-WindowsFeature | Where-Object Installed)
            } else {
                Write-Warning -Message 'Unable to retrieve installed features as ServerManager module not available.'
                $VitalInformation.InstalledFeatures = $false
            }
        } else {
            Write-Verbose -Message 'Unable to retrieve installed features as not running on Windows Server.'
            $VitalInformation.InstalledFeatures = $false
        }
        $TasksDone++
    }

    if ($Tasks['InstalledPrograms']) {
        Write-Progress @WriteProgressParams -Status 'Retrieving installed programs' -PercentComplete ($TasksDone / $TasksTotal * 100)
        $VitalInformation.InstalledPrograms = Get-InstalledPrograms
        $TasksDone++
    }

    if ($Tasks['EnvironmentVariables']) {
        Write-Progress @WriteProgressParams -Status 'Retrieving environment variables' -PercentComplete ($TasksDone / $TasksTotal * 100)

        $EnvironmentVariables = [PSCustomObject]@{
            Machine = $null
            User    = $null
        }
        $EnvironmentVariables.PSObject.TypeNames.Insert(0, 'PSWinVitals.EnvironmentVariables')

        $Machine = [Ordered]@{}
        $MachineVariables = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
        foreach ($Variable in ($MachineVariables.Keys | Sort-Object)) {
            $Machine[$Variable] = $MachineVariables[$Variable]
        }
        $EnvironmentVariables.Machine = $Machine

        $User = [Ordered]@{}
        $UserVariables = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
        foreach ($Variable in ($UserVariables.Keys | Sort-Object)) {
            $User[$Variable] = $UserVariables[$Variable]
        }
        $EnvironmentVariables.User = $User

        $VitalInformation.EnvironmentVariables = $EnvironmentVariables
        $TasksDone++
    }

    if ($Tasks['WindowsUpdates']) {
        if (Get-Module -Name 'PSWindowsUpdate' -ListAvailable -Verbose:$false) {
            Write-Progress @WriteProgressParams -Status 'Retrieving Windows updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $WindowsUpdates = Get-WindowsUpdate @WUParameters

            if ($null -ne $WindowsUpdates -and $WindowsUpdates.Count -gt 0) {
                $VitalInformation.WindowsUpdates = New-Object -TypeName 'Collections.ArrayList' -ArgumentList @(, $WindowsUpdates)
            } else {
                $VitalInformation.WindowsUpdates = New-Object -TypeName 'Collections.ArrayList'
            }
        } else {
            Write-Warning -Message 'Unable to retrieve Windows updates as PSWindowsUpdate module not available.'
            $VitalInformation.WindowsUpdates = $false
        }
        $TasksDone++
    }

    if ($Tasks['SysinternalsSuite']) {
        if (Test-IsWindows64bit) {
            $InstallDir = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Sysinternals'
        } else {
            $InstallDir = Join-Path -Path $env:ProgramFiles -ChildPath 'Sysinternals'
        }

        if (Test-Path -Path $InstallDir -PathType Container) {
            Write-Progress @WriteProgressParams -Status 'Retrieving Sysinternals Suite version' -PercentComplete ($TasksDone / $TasksTotal * 100)

            $Sysinternals = [PSCustomObject]@{
                Path    = $InstallDir
                Version = $null
            }

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
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
    return $VitalInformation
}

Function Invoke-VitalChecks {
    <#
        .SYNOPSIS
        Performs system health checks

        .DESCRIPTION
        The following tasks are available:
        - ComponentStoreScan
          Scans the component store and repairs any corruption.

          If the -VerifyOnly parameter is specified then no repairs will be performed.

          This task requires administrator privileges.

        - FileSystemScans
          Scans all non-removable storage volumes with supported file systems and repairs any corruption.

          If the -VerifyOnly parameter is specified then no repairs will be performed.

          Volumes using FAT file systems are only supported with -VerifyOnly as they do not support online repair.

          This task requires administrator privileges and Windows 8, Windows Server 2012, or newer.

        - SystemFileChecker
          Scans system files and repairs any corruption.

          If the -VerifyOnoly parameter is specified then no repairs will be performed.

          This task requires administrator privileges.

        The default is to run all tasks.

        .PARAMETER ExcludeTasks
        Array of tasks to exclude. The default is an empty array (i.e. run all tasks).

        .PARAMETER IncludeTasks
        Array of tasks to include. At least one task must be specified.

        .PARAMETER VerifyOnly
        Modifies the behaviour of health checks to not repair any issues.

        .EXAMPLE
        Invoke-VitalChecks -IncludeTasks FileSystemScans -VerifyOnly

        Only runs file system scans without performing any repairs.

        .NOTES
        Selected health checks are run in the following order:
        - FileSystemScans
        - SystemFileChecker
        - ComponentStoreScan

        .LINK
        https://github.com/ralish/PSWinVitals
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(DefaultParameterSetName = 'OptOut')]
    Param(
        [Parameter(ParameterSetName = 'OptOut')]
        [ValidateSet(
            'ComponentStoreScan',
            'FileSystemScans',
            'SystemFileChecker'
        )]
        [String[]]$ExcludeTasks,

        [Parameter(ParameterSetName = 'OptIn', Mandatory)]
        [ValidateSet(
            'ComponentStoreScan',
            'FileSystemScans',
            'SystemFileChecker'
        )]
        [String[]]$IncludeTasks,

        [Switch]$VerifyOnly
    )

    if (!(Test-IsAdministrator)) {
        throw 'You must have administrator privileges to perform system health checks.'
    }

    $Tasks = @{
        ComponentStoreScan = $null
        FileSystemScans    = $null
        SystemFileChecker  = $null
    }

    $TasksDone = 0
    $TasksTotal = 0

    foreach ($Task in @($Tasks.Keys)) {
        if ($PSCmdlet.ParameterSetName -eq 'OptOut') {
            if ($ExcludeTasks -contains $Task) {
                $Tasks[$Task] = $false
            } else {
                $Tasks[$Task] = $true
                $TasksTotal++
            }
        } else {
            if ($IncludeTasks -contains $Task) {
                $Tasks[$Task] = $true
                $TasksTotal++
            } else {
                $Tasks[$Task] = $false
            }
        }
    }

    $VitalChecks = [PSCustomObject]@{
        ComponentStoreScan = $null
        FileSystemScans    = $null
        SystemFileChecker  = $null
    }
    $VitalChecks.PSObject.TypeNames.Insert(0, 'PSWinVitals.VitalChecks')

    $WriteProgressParams = @{
        Activity = 'Running vital checks'
    }

    if ($Tasks['FileSystemScans']) {
        if (Get-Module -Name 'Storage' -ListAvailable -Verbose:$false) {
            Write-Progress @WriteProgressParams -Status 'Running file system scans' -PercentComplete ($TasksDone / $TasksTotal * 100)
            if ($VerifyOnly) {
                $VitalChecks.FileSystemScans = Invoke-CHKDSK -Operation Verify
            } else {
                $VitalChecks.FileSystemScans = Invoke-CHKDSK -Operation Scan
            }
        } else {
            Write-Warning -Message 'Unable to run file system scans as Storage module not available.'
            $VitalChecks.FileSystemScans = $false
        }
        $TasksDone++
    }

    if ($Tasks['ComponentStoreScan']) {
        Write-Progress @WriteProgressParams -Status 'Running component store scan' -PercentComplete ($TasksDone / $TasksTotal * 100)
        if ($VerifyOnly) {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation ScanHealth
        } else {
            $VitalChecks.ComponentStoreScan = Invoke-DISM -Operation RestoreHealth
        }
        $TasksDone++
    }

    if ($Tasks['SystemFileChecker']) {
        Write-Progress @WriteProgressParams -Status 'Running System File Checker' -PercentComplete ($TasksDone / $TasksTotal * 100)
        if ($VerifyOnly) {
            $VitalChecks.SystemFileChecker = Invoke-SFC -Operation Verify
        } else {
            $VitalChecks.SystemFileChecker = Invoke-SFC -Operation Scan
        }
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
    return $VitalChecks
}

Function Invoke-VitalMaintenance {
    <#
        .SYNOPSIS
        Performs system maintenance tasks

        .DESCRIPTION
        The following tasks are available:
        - ClearInternetExplorerCache
          Clears all cached Internet Explorer data for the user.

        - ComponentStoreCleanup
          Performs a component store clean-up to remove obsolete Windows updates.

          This task requires administrator privileges.

        - DeleteErrorReports
          Deletes all error reports (queued & archived) for the system and user.

          This task requires administrator privileges.

        - DeleteTemporaryFiles
          Recursively deletes all data in the following locations:
          * The "TEMP" environment variable path for the system
          * The "TEMP" environment variable path for the user

          This task requires administrator privileges.

        - EmptyRecycleBin
          Empties the Recycle Bin for the user.

          This task requires Windows 10, Windows Server 2016, or newer.

        - PowerShellHelp
          Updates PowerShell help for all modules.

          This task requires administrator privileges.

        - SysinternalsSuite
          Downloads and installs the latest Sysinternals Suite.

          The installation process itself consists of the following steps:
          * Download the latest Sysinternals Suite archive from download.sysinternals.com
          * Determine the version based off the date of the most recently modified file in the archive
          * If the downloaded version is newer than the installed version (if any is present) then:
          | * Remove any existing files in the installation directory and decompress the downloaded archive
          | * Write a Version.txt file in the installation directory with earlier determined version date
          * Add the installation directory to the system path environment variable if it's not already present

          The location where the utilities will be installed depends on the OS architecture:
          * 32-bit: The "Sysinternals" folder in the "Program Files" directory
          * 64-bit: The "Sysinternals" folder in the "Program Files (x86)" directory

          This task requires administrator privileges.

        - WindowsUpdates
          Downloads and installs all available Windows updates.

          Updates from Microsoft Update are also included if opted-in via the Windows Update configuration.

          This task requires administrator privileges and the PSWindowsUpdate module.

        The default is to run all tasks.

        .PARAMETER ExcludeTasks
        Array of tasks to exclude. The default is an empty array (i.e. run all tasks).

        .PARAMETER IncludeTasks
        Array of tasks to include. At least one task must be specified.

        .PARAMETER WUParameters
        Hashtable of additional parameters to pass to Install-WindowsUpdate.

        The -IgnoreReboot and -AcceptAll parameters are set by default.

        Only used if the WindowsUpdates task is selected.

        .EXAMPLE
        Invoke-VitalMaintenance -IncludeTasks WindowsUpdates, SysinternalsSuite -WUParameters @{NotTitle = 'Silverlight'}

        Only install Windows updates and the latest Sysinternals utilities. Exclude updates with Silverlight in the title.

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

    [CmdletBinding(DefaultParameterSetName = 'OptOut')]
    Param(
        [Parameter(ParameterSetName = 'OptOut')]
        [ValidateSet(
            'ComponentStoreCleanup',
            'ClearInternetExplorerCache',
            'DeleteErrorReports',
            'DeleteTemporaryFiles',
            'EmptyRecycleBin',
            'PowerShellHelp',
            'SysinternalsSuite',
            'WindowsUpdates'
        )]
        [String[]]$ExcludeTasks,

        [Parameter(ParameterSetName = 'OptIn', Mandatory)]
        [ValidateSet(
            'ComponentStoreCleanup',
            'ClearInternetExplorerCache',
            'DeleteErrorReports',
            'DeleteTemporaryFiles',
            'EmptyRecycleBin',
            'PowerShellHelp',
            'SysinternalsSuite',
            'WindowsUpdates'
        )]
        [String[]]$IncludeTasks,

        [ValidateNotNull()]
        [Hashtable]$WUParameters = @{}
    )

    if (!(Test-IsAdministrator)) {
        throw 'You must have administrator privileges to perform system maintenance.'
    }

    $Tasks = @{
        ClearInternetExplorerCache = $null
        ComponentStoreCleanup      = $null
        DeleteErrorReports         = $null
        DeleteTemporaryFiles       = $null
        EmptyRecycleBin            = $null
        PowerShellHelp             = $null
        SysinternalsSuite          = $null
        WindowsUpdates             = $null
    }

    $TasksDone = 0
    $TasksTotal = 0

    foreach ($Task in @($Tasks.Keys)) {
        if ($PSCmdlet.ParameterSetName -eq 'OptOut') {
            if ($ExcludeTasks -contains $Task) {
                $Tasks[$Task] = $false
            } else {
                $Tasks[$Task] = $true
                $TasksTotal++
            }
        } else {
            if ($IncludeTasks -contains $Task) {
                $Tasks[$Task] = $true
                $TasksTotal++
            } else {
                $Tasks[$Task] = $false
            }
        }
    }

    $VitalMaintenance = [PSCustomObject]@{
        ClearInternetExplorerCache = $null
        ComponentStoreCleanup      = $null
        DeleteErrorReports         = $null
        DeleteTemporaryFiles       = $null
        EmptyRecycleBin            = $null
        PowerShellHelp             = $null
        SysinternalsSuite          = $null
        WindowsUpdates             = $null
    }
    $VitalMaintenance.PSObject.TypeNames.Insert(0, 'PSWinVitals.VitalMaintenance')

    $WriteProgressParams = @{
        Activity = 'Running vital maintenance'
    }

    if ($Tasks['WindowsUpdates']) {
        try {
            Import-Module -Name 'PSWindowsUpdate' -ErrorAction Stop -Verbose:$false
        } catch [IO.FileNotFoundException] {
            Write-Warning -Message 'Unable to install Windows updates as PSWindowsUpdate module not available.'
            $VitalMaintenance.WindowsUpdates = $false
        }

        if ($null -eq $VitalMaintenance.WindowsUpdates) {
            Write-Progress @WriteProgressParams -Status 'Installing Windows updates' -PercentComplete ($TasksDone / $TasksTotal * 100)
            $WindowsUpdates = Install-WindowsUpdate -IgnoreReboot -AcceptAll @WUParameters

            if ($null -ne $WindowsUpdates -and $WindowsUpdates.Count -gt 0) {
                $VitalMaintenance.WindowsUpdates = New-Object -TypeName 'Collections.ArrayList' -ArgumentList @(, $WindowsUpdates)
            } else {
                $VitalMaintenance.WindowsUpdates = New-Object -TypeName 'Collections.ArrayList'
            }
        }

        $TasksDone++
    }

    if ($Tasks['ComponentStoreCleanup']) {
        Write-Progress @WriteProgressParams -Status 'Running component store clean-up' -PercentComplete ($TasksDone / $TasksTotal * 100)
        $VitalMaintenance.ComponentStoreCleanup = Invoke-DISM -Operation StartComponentCleanup
        $TasksDone++
    }

    if ($Tasks['PowerShellHelp']) {
        Write-Progress @WriteProgressParams -Status 'Updating PowerShell help' -PercentComplete ($TasksDone / $TasksTotal * 100)
        try {
            Update-Help -Force -ErrorAction Stop
            $VitalMaintenance.PowerShellHelp = $true
        } catch {
            # Many modules don't define the HelpInfoUri key in their manifest,
            # which will cause Update-Help to log an error. This should really
            # be treated as a warning.
            $VitalMaintenance.PowerShellHelp = $_.Exception.Message
        }
        $TasksDone++
    }

    if ($Tasks['SysinternalsSuite']) {
        Write-Progress @WriteProgressParams -Status 'Updating Sysinternals suite' -PercentComplete ($TasksDone / $TasksTotal * 100)
        $VitalMaintenance.SysinternalsSuite = Update-Sysinternals
        $TasksDone++
    }

    if ($Tasks['ClearInternetExplorerCache']) {
        if (Get-Command -Name 'inetcpl.cpl' -ErrorAction Ignore) {
            Write-Progress @WriteProgressParams -Status 'Clearing Internet Explorer cache' -PercentComplete ($TasksDone / $TasksTotal * 100)
            # More details on the bitmask here:
            # https://github.com/SeleniumHQ/selenium/blob/master/cpp/iedriver/BrowserFactory.cpp
            $RunDll32Path = Join-Path -Path $env:SystemRoot -ChildPath 'System32\rundll32.exe'
            Start-Process -FilePath $RunDll32Path -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess', '9FF' -Wait
            $VitalMaintenance.ClearInternetExplorerCache = $true
        } else {
            Write-Warning -Message 'Unable to clear Internet Explorer cache as Control Panel applet not available.'
            $VitalMaintenance.ClearInternetExplorerCache = $false
        }
        $TasksDone++
    }

    if ($Tasks['DeleteErrorReports']) {
        Write-Progress @WriteProgressParams -Status 'Deleting error reports' -PercentComplete ($TasksDone / $TasksTotal * 100)

        $SystemReports = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\WER'
        $SystemQueue = Join-Path -Path $SystemReports -ChildPath 'ReportQueue'
        $SystemArchive = Join-Path -Path $SystemReports -ChildPath 'ReportArchive'
        foreach ($Path in @($SystemQueue, $SystemArchive)) {
            if (Test-Path -Path $Path -PathType Container) {
                Remove-Item -Path "$Path\*" -Recurse -ErrorAction Ignore
            }
        }

        $UserReports = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\WER'
        $UserQueue = Join-Path -Path $UserReports -ChildPath 'ReportQueue'
        $UserArchive = Join-Path -Path $UserReports -ChildPath 'ReportArchive'
        foreach ($Path in @($UserQueue, $UserArchive)) {
            if (Test-Path -Path $Path -PathType Container) {
                Remove-Item -Path "$Path\*" -Recurse -ErrorAction Ignore
            }
        }

        $VitalMaintenance.DeleteErrorReports = $true
        $TasksDone++
    }

    if ($Tasks['DeleteTemporaryFiles']) {
        Write-Progress @WriteProgressParams -Status 'Deleting temporary files' -PercentComplete ($TasksDone / $TasksTotal * 100)

        $SystemTemp = [Environment]::GetEnvironmentVariable('Temp', [EnvironmentVariableTarget]::Machine)
        Remove-Item -Path "$SystemTemp\*" -Recurse -ErrorAction Ignore
        Remove-Item -Path "$env:TEMP\*" -Recurse -ErrorAction Ignore

        $VitalMaintenance.DeleteTemporaryFiles = $true
        $TasksDone++
    }

    if ($Tasks['EmptyRecycleBin']) {
        if (Get-Command -Name 'Clear-RecycleBin' -ErrorAction Ignore) {
            Write-Progress @WriteProgressParams -Status 'Emptying Recycle Bin' -PercentComplete ($TasksDone / $TasksTotal * 100)
            try {
                Clear-RecycleBin -Force -ErrorAction Stop
                $VitalMaintenance.EmptyRecycleBin = $true
            } catch [ComponentModel.Win32Exception] {
                # Sometimes clearing the Recycle Bin fails with an exception
                # indicating the Recycle Bin directory doesn't exist. Only a
                # generic E_FAIL exception is thrown though, so inspect the
                # actual exception message to be sure.
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
        $TasksDone++
    }

    Write-Progress @WriteProgressParams -Completed
    return $VitalMaintenance
}

Function Get-HypervisorInfo {
    [CmdletBinding()]
    Param()

    $LogPrefix = 'HypervisorInfo'
    $HypervisorInfo = [PSCustomObject]@{
        Vendor       = $null
        Hypervisor   = $null
        ToolsVersion = $null
    }

    $ComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem' -Verbose:$false
    $Manufacturer = $ComputerSystem.Manufacturer
    $Model = $ComputerSystem.Model

    # Useful:
    # http://git.annexia.org/?p=virt-what.git;a=blob_plain;f=virt-what.in;hb=HEAD
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param()

    Add-NativeMethods

    $InstalledPrograms = New-Object -TypeName 'Collections.ArrayList'

    # Programs installed system-wide in native bitness
    $ComputerNativeRegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    # Programs installed system-wide under the 32-bit emulation layer (64-bit Windows only)
    $ComputerWow64RegPath = 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

    # Retrieve all installed programs from available keys
    $UninstallKeys = Get-ChildItem -Path $ComputerNativeRegPath
    if (Test-Path -Path $ComputerWow64RegPath -PathType Container) {
        $UninstallKeys += Get-ChildItem -Path $ComputerWow64RegPath
    }

    # Filter out all the uninteresting installations
    foreach ($UninstallKey in $UninstallKeys) {
        $Program = Get-ItemProperty -Path $UninstallKey.PSPath

        # Skip any program which doesn't define a display name
        if (!$Program.PSObject.Properties['DisplayName']) {
            continue
        }

        # Skip any program without an uninstall command which is not marked non-removable
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
            PSPath        = $Program.PSPath
            Name          = $Program.DisplayName
            Publisher     = $null
            InstallDate   = $null
            EstimatedSize = $null
            Version       = $null
            Location      = $null
            Uninstall     = $null
        }
        $InstalledProgram.PSObject.TypeNames.Insert(0, 'PSWinVitals.InstalledProgram')

        if ($Program.PSObject.Properties['Publisher']) {
            $InstalledProgram.Publisher = $Program.Publisher
        }

        # Try and convert the InstallDate value to a DateTime
        if ($Program.PSObject.Properties['InstallDate']) {
            $RegInstallDate = $Program.InstallDate
            if ($RegInstallDate -match '^[0-9]{8}') {
                try {
                    $InstalledProgram.InstallDate = New-Object -TypeName 'DateTime' -ArgumentList $RegInstallDate.Substring(0, 4), $RegInstallDate.Substring(4, 2), $RegInstallDate.Substring(6, 2)
                } catch { }
            }

            if (!$InstalledProgram.InstallDate) {
                Write-Warning -Message ('[{0}] Registry key has invalid value for InstallDate: {1}' -f $Program.DisplayName, $RegInstallDate)
            }
        }

        # Fall back to the last write time of the registry key
        if (!$InstalledProgram.InstallDate) {
            [UInt64]$RegLastWriteTime = 0
            $Status = [PSWinVitals.NativeMethods]::RegQueryInfoKey($UninstallKey.Handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$RegLastWriteTime)

            if ($Status -eq 0) {
                $InstalledProgram.InstallDate = [DateTime]::FromFileTime($RegLastWriteTime)
            } else {
                Write-Warning -Message ('[{0}] Retrieving registry key last write time failed with status: {1}' -f $Program.DisplayName, $Status)
            }
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

        $null = $InstalledPrograms.Add($InstalledProgram)
    }

    return , @($InstalledPrograms | Sort-Object -Property Name)
}

Function Get-KernelCrashDumps {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param()

    $LogPrefix = 'KernelCrashDumps'
    $KernelCrashDumps = [PSCustomObject]@{
        MemoryDump = $null
        Minidumps  = $null
    }
    $KernelCrashDumps.PSObject.TypeNames.Insert(0, 'PSWinVitals.KernelCrashDumps')

    $CrashControlRegPath = 'HKLM:\System\CurrentControlSet\Control\CrashControl'

    if (Test-Path -Path $CrashControlRegPath -PathType Container) {
        $CrashControl = Get-ItemProperty -Path $CrashControlRegPath

        if ($CrashControl.PSObject.Properties['DumpFile']) {
            $DumpFile = $CrashControl.DumpFile
        } else {
            $DumpFile = Join-Path -Path $env:SystemRoot -ChildPath 'MEMORY.DMP'
            Write-Warning -Message ("[{0}] Guessing the location as DumpFile value doesn't exist under the CrashControl registry key." -f $LogPrefix)
        }

        if ($CrashControl.PSObject.Properties['MinidumpDir']) {
            $MinidumpDir = $CrashControl.MinidumpDir
        } else {
            $DumpFile = Join-Path -Path $env:SystemRoot -ChildPath 'Minidump'
            Write-Warning -Message ("[{0}] Guessing the location as MinidumpDir value doesn't exist under CrashControl registry key." -f $LogPrefix)
        }
    } else {
        Write-Warning -Message ("[{0}] Guessing dump locations as the CrashControl registry key doesn't exist." -f $LogPrefix)
    }

    if (Test-Path -Path $DumpFile -PathType Leaf) {
        $KernelCrashDumps.MemoryDump = Get-Item -Path $DumpFile
    }

    if (Test-Path -Path $MinidumpDir -PathType Container) {
        $KernelCrashDumps.Minidumps = @(Get-ChildItem -Path $MinidumpDir)
    }

    return $KernelCrashDumps
}

Function Get-ServiceCrashDumps {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param()

    $LogPrefix = 'ServiceCrashDumps'
    $ServiceCrashDumps = New-Object -TypeName 'Collections.ArrayList'

    $null = $ServiceCrashDumps.Add((Get-UserProfileCrashDumps -Sid 'S-1-5-18' -Name 'LocalSystem' -LogPrefix $LogPrefix))
    $null = $ServiceCrashDumps.Add((Get-UserProfileCrashDumps -Sid 'S-1-5-19' -Name 'LocalService' -LogPrefix $LogPrefix))
    $null = $ServiceCrashDumps.Add((Get-UserProfileCrashDumps -Sid 'S-1-5-20' -Name 'NetworkService' -LogPrefix $LogPrefix))

    return $ServiceCrashDumps
}

Function Get-UserCrashDumps {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param()

    $LogPrefix = 'UserCrashDumps'
    $UserCrashDumps = New-Object -TypeName 'Collections.ArrayList'

    $ProfileList = Get-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $UserSids = $ProfileList.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-' }
    foreach ($UserSid in $UserSids) {
        $null = $UserCrashDumps.Add((Get-UserProfileCrashDumps -Sid $UserSid -LogPrefix $LogPrefix))
    }

    return , @($UserCrashDumps)
}

Function Get-UserProfileCrashDumps {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Sid,

        [ValidateNotNullOrEmpty()]
        [String]$Name,

        [ValidateNotNullOrEmpty()]
        [String]$LogPrefix = 'UserProfileCrashDumps'
    )

    $UserProfileRegPath = Join-Path -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' -ChildPath $Sid
    try {
        $UserProfile = Get-ItemProperty -Path $UserProfileRegPath -ErrorAction Stop
    } catch {
        Write-Warning -Message ('[{0}] Failed to retrieve user profile information for SID: {1}' -f $LogPrefix, $Sid)
        return
    }

    if ($UserProfile.PSObject.Properties['ProfileImagePath']) {
        $ProfileImagePath = $UserProfile.ProfileImagePath
    } else {
        Write-Warning -Message ('[{0}] User profile information has no ProfileImagePath for SID: {1}' -f $LogPrefix, $Sid)
        return
    }

    if (!$Name) {
        $Name = Split-Path -Path $ProfileImagePath -Leaf
    }

    $CrashDumps = [PSCustomObject]@{
        Name       = $Name
        Crashdumps = $null
    }
    $CrashDumps.PSObject.TypeNames.Insert(0, 'PSWinVitals.UserProfileCrashDumps')

    $CrashDumpsPath = Join-Path -Path $ProfileImagePath -ChildPath 'AppData\Local\CrashDumps'
    try {
        $CrashDumps.CrashDumps = @(Get-ChildItem -Path $CrashDumpsPath -ErrorAction Stop)
    } catch {
        Write-Verbose -Message ('[{0}] The crash dumps path for the user does not exist: {1}' -f $LogPrefix, $Name)
    }

    return $CrashDumps
}

Function Invoke-CHKDSK {
    [CmdletBinding()]
    Param(
        [ValidateSet('Scan', 'Verify')]
        [String]$Operation = 'Scan'
    )

    # We could use the Repair-Volume cmdlet introduced in Windows 8 and Server
    # 2012, but it's just a thin wrapper around CHKDSK and only exposes a small
    # subset of its underlying functionality.
    $LogPrefix = 'CHKDSK'

    # Supported file systems for scanning for errors (Verify)
    $SupportedFileSystems = @('exFAT', 'FAT', 'FAT16', 'FAT32', 'NTFS', 'NTFS4', 'NTFS5')
    # Supported file system for scanning for errors and fixing (Scan)
    #
    # FAT volumes don't support online repair so fixing errors means
    # dismounting the volume. No parameter equivalent to "dismount only if
    # safe" exists so for now we don't support reparing these volumes.
    $ScanSupportedFileSystems = @('NTFS', 'NTFS4', 'NTFS5')

    $Volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -in $SupportedFileSystems }

    $Results = New-Object -TypeName 'Collections.ArrayList'
    foreach ($Volume in $Volumes) {
        $VolumePath = $Volume.Path.TrimEnd('\')

        if ($Operation -eq 'Scan' -and $Volume.FileSystem -notin $ScanSupportedFileSystems) {
            Write-Warning -Message ('[{0}] Skipping volume as non-interactive repair of {1} file systems is unsupported: {2}' -f $LogPrefix, $Volume.FileSystem, $VolumePath)
            continue
        }

        if ($Operation -eq 'Scan' -and $VolumePath -eq '\\?\Volume{629458e4-0000-0000-0000-010000000000}') {
            Write-Warning -Message ('[{0}] Skipping {1} volume as shadow copying the volume is not supported.' -f $LogPrefix, $Volume.FileSystemLabel)
            continue
        }

        $CHKDSK = [PSCustomObject]@{
            Operation  = $Operation
            VolumePath = $VolumePath
            Output     = $null
            ExitCode   = $null
        }
        $CHKDSK.PSObject.TypeNames.Insert(0, 'PSWinVitals.CHKDSK')

        Write-Verbose -Message ('[{0}] Running {1} operation on: {2}' -f $LogPrefix, $Operation.ToLower(), $VolumePath)
        $ChkDskPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\chkdsk.exe'
        if ($Operation -eq 'Scan') {
            $CHKDSK.Output += & $ChkDskPath $VolumePath /scan
        } else {
            $CHKDSK.Output += & $ChkDskPath $VolumePath
        }
        $CHKDSK.ExitCode = $LASTEXITCODE

        switch ($CHKDSK.ExitCode) {
            0 { continue }
            2 { Write-Warning -Message ('[{0}] Volume requires cleanup: {1}' -f $LogPrefix, $VolumePath) }
            3 { Write-Warning -Message ('[{0}] Volume contains errors: {1}' -f $LogPrefix, $VolumePath) }
            default { Write-Error -Message ('[{0}] Unexpected exit code: {1}' -f $LogPrefix, $CHKDSK.ExitCode) }
        }

        $null = $Results.Add($CHKDSK)
    }

    return , @($Results)
}

Function Invoke-DISM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateSet('AnalyzeComponentStore', 'RestoreHealth', 'ScanHealth', 'StartComponentCleanup')]
        [String]$Operation
    )

    # The Dism module doesn't include cmdlets which map to the /Cleanup-Image
    # functionality in the underlying Dism.exe utility, so it's necessary to
    # invoke it directly.
    $LogPrefix = 'DISM'
    $DISM = [PSCustomObject]@{
        Operation = $Operation
        Output    = $null
        ExitCode  = $null
    }
    $DISM.PSObject.TypeNames.Insert(0, 'PSWinVitals.DISM')

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

    <#
        SFC is a horror show when it comes to capturing its output:

        1. In contrast to most (every?) other built-in Windows console app, SFC
           output is UTF-16LE. PowerShell is probably expecting windows-1252 (a
           superset of ASCII), so the output will be decoded incorrectly. Fix
           this by temporarily setting the OutputEncoding property of the
           Console static class to Unicode, which specifies the character
           encoding used by native applications.

        2. It outputs \r\r\n sequences for newlines (yes, really). PowerShell
           interprets this character sequence as two newlines so the output
           must be filtered to remove the extras.

        3. When running in a remote session via WinRM we're not running under a
           console, which results in an invalid handle exception on setting
           [Console]::OutputEncoding. Actually, that's not entirely true; it
           works when setting it to [Text.Encoding]::Unicode (i.e. UTF-16LE),
           which is what we want, but will throw an exception on changing it
           back to anything else (including the original value). This causes
           broken output for any subsequent app that's called (except SFC).

           The solution to this craziness is to manually allocate a console
           with AllocConsole() and free it with FreeConsole(). This spawns a
           ConsoleHost.exe process allowing us to set [Console]::OutputEncoding
           without hitting an invalid handle exception. SFC spawns a Console
           Host itself anyway if it doesn't inherit a console from the parent
           process, so this happens regardless; we're just attaching a console
           to PowerShell directly instead.

        Bonus extra confusion: you'll probably find SFC works just fine if you
        invoke it directly in PowerShell. That's because the problem happens
        when *redirecting* the output. It seems that if SFC output is not being
        redirected it just directly writes to the console via WriteConsole().
        Except under WinRM, where it's always broken, presumably because its
        output is being redirected at some level being under a remote session.

        Useful references:
        - https://stackoverflow.com/a/57751203/8787985
        - https://computerexpress1.blogspot.com/2017/11/powershell-and-cyrillic-in-console.html
    #>

    Add-NativeMethods

    $LogPrefix = 'SFC'
    $SFC = [PSCustomObject]@{
        Operation = $Operation
        Output    = $null
        ExitCode  = $null
    }
    $SFC.PSObject.TypeNames.Insert(0, 'PSWinVitals.SFC')

    $AllocatedConsole = $false
    $DefaultOutputEncoding = [Console]::OutputEncoding

    # If AllocConsole() returns false a console is probably already attached
    if ([PSWinVitals.NativeMethods]::AllocConsole()) {
        Write-Debug -Message ('[{0}] Allocated a new console.' -f $LogPrefix, $Operation.ToLower())
        $AllocatedConsole = $true
    }

    Write-Debug -Message ('[{0}] Setting console output encoding to Unicode.' -f $LogPrefix, $Operation.ToLower())
    [Console]::OutputEncoding = [Text.Encoding]::Unicode

    Write-Verbose -Message ('[{0}] Running {1} operation ...' -f $LogPrefix, $Operation.ToLower())
    $SfcPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\sfc.exe'
    if ($Operation -eq 'Scan') {
        $SfcParam = '/SCANNOW'
    } else {
        $SfcParam = '/VERIFYONLY'
    }
    # Remove the duplicate newlines and split on them for a string array output
    $SFC.Output = ((& $SfcPath $SfcParam) -join "`r`n" -replace "`r`n`r`n", "`r`n") -split "`r`n"
    $SFC.ExitCode = $LASTEXITCODE

    Write-Debug -Message ('[{0}] Restoring original console output encoding.' -f $LogPrefix, $Operation.ToLower())
    [Console]::OutputEncoding = $DefaultOutputEncoding

    if ($AllocatedConsole) {
        Write-Debug -Message ('[{0}] Freeing allocated console.' -f $LogPrefix, $Operation.ToLower())
        if (![PSWinVitals.NativeMethods]::FreeConsole()) {
            $Win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error -Message ('Failed to free allocated console with error: {0}' -f $Win32Error)
        }
    }

    switch ($SFC.ExitCode) {
        0 { continue }
        default { Write-Error -Message ('[{0}] Returned non-zero exit code: {1}' -f $LogPrefix, $SFC.ExitCode) }
    }

    return $SFC
}

Function Update-Sysinternals {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param(
        [ValidatePattern('^http[Ss]?://.*')]
        [String]$DownloadUrl = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    )

    $LogPrefix = 'Sysinternals'
    $Sysinternals = [PSCustomObject]@{
        Path    = $null
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
    $WebClient = New-Object -TypeName 'Net.WebClient'
    try {
        $WebClient.DownloadFile($DownloadUrl, $DownloadPath)
    } catch {
        # Return immediately with the error message if the download fails
        return $_.Exception.Message
    }

    Write-Verbose -Message ('[{0}] Determining downloaded version ...' -f $LogPrefix)
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    $Archive = [IO.Compression.ZipFile]::OpenRead($DownloadPath)
    $DownloadedVersion = ($Archive.Entries.LastWriteTime | Sort-Object | Select-Object -Last 1).ToString('yyyyMMdd')
    $Archive.Dispose()

    if (!$ExistingVersion -or ($DownloadedVersion -gt $ExistingVersion)) {
        Write-Verbose -Message ('[{0}] Extracting archive to: {1}' -f $LogPrefix, $InstallDir)
        Remove-Item -Path $InstallDir -Recurse -ErrorAction Ignore
        # The -Force parameter shouldn't be necessary given we've removed any
        # existing files, except sometimes the archive has files differing only
        # by case. Permit overwriting of files as a workaround and we just have
        # to hope any overwritten files were older.
        Expand-ZipFile -FilePath $DownloadPath -DestinationPath $InstallDir -Force
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

Function Add-NativeMethods {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    Param()

    if (!('PSWinVitals.NativeMethods' -as [Type])) {
        $NativeMethods = @'
[DllImport("kernel32.dll", SetLastError = true)]
public extern static bool AllocConsole();

[DllImport("kernel32.dll", SetLastError = true)]
public extern static bool FreeConsole();

[DllImport("advapi32.dll", EntryPoint = "RegQueryInfoKeyW")]
public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
                                         IntPtr lpClass,
                                         IntPtr lpcchClass,
                                         IntPtr lpReserved,
                                         IntPtr lpcSubKeys,
                                         IntPtr lpcbMaxSubKeyLen,
                                         IntPtr lpcbMaxClassLen,
                                         IntPtr lpcValues,
                                         IntPtr lpcbMaxValueNameLen,
                                         IntPtr lpcbMaxValueLen,
                                         IntPtr lpcbSecurityDescriptor,
                                         out UInt64 lpftLastWriteTime);
'@

        $AddTypeParams = @{}

        if ($PSVersionTable['PSEdition'] -eq 'Core') {
            $AddTypeParams['ReferencedAssemblies'] = 'Microsoft.Win32.Registry'
        }

        Add-Type -Namespace 'PSWinVitals' -Name 'NativeMethods' -MemberDefinition $NativeMethods @AddTypeParams
    }
}

Function Expand-ZipFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$FilePath,

        [Parameter(Mandatory)]
        [String]$DestinationPath,

        [Switch]$Force
    )

    # The Expand-Archive cmdlet is only available from PowerShell v5.0
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Expand-Archive -Path $FilePath -DestinationPath $DestinationPath -Force:$Force
    } else {
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
        [IO.Compression.ZipFile]::ExtractToDirectory($FilePath, $DestinationPath, $Force)
    }
}

Function Get-WindowsProductType {
    [CmdletBinding()]
    Param()

    return (Get-CimInstance -ClassName 'Win32_OperatingSystem' -Verbose:$false).ProductType
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

    if ((Get-CimInstance -ClassName 'Win32_OperatingSystem' -Verbose:$false).OSArchitecture -eq '64-bit') {
        return $true
    }

    return $false
}
