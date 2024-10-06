Changelog
=========

v0.7.0
------

- `Invoke-VitalMaintenance`: Add support for running NGEN with new `DotNetQueuedItems` task

v0.6.9
------

- `Get-InstalledPrograms`: Fix invalid syntax (affects PowerShell 7.4)

v0.6.8
------

- Fix incorrect count of crash dumps in type formatting

v0.6.7
------

- Fix compatibility due to earlier PowerShell releases not having a type accelerator for `UInt`

v0.6.6
------

- Minor code clean-up & developer tooling improvements

v0.6.5
------

- `Invoke-VitalMaintenance`: Fix divide by zero error due to progress bar handling bug

v0.6.4
------

- Add progress bar support to all commands

v0.6.3
------

- `Get-VitalInformation`: Fix incorrect crash dumps count in output formatting

v0.6.2
------

- `Get-VitalInformation`: The `CrashDumps` task now also checks for crashdumps under each user profile
- `Get-VitalInformation`: The `EnvironmentVariables` task now returns results sorted by variable name
- `Get-VitalInformation`: Smarter handling of tasks requiring administrator privileges (see help)
- Added additional type format data & tweaks to existing formats
- Minor documentation updates & miscellaneous fixes

v0.6.1
------

- `Get-VitalInformation`: Fix array passing bug to the `ArrayList` constructor on retrieving Windows Updates
- `Invoke-VitalMaintenance`: Fix array passing bug to the `ArrayList` constructor on installing Windows Updates

v0.6.0
------

- **All commands**: Add type format data so default output is much easier to parse

v0.5.1
------

- `Invoke-VitalMaintenance`: Permit overwriting files during Sysinternals extraction due to files in archive differing only by case (*upstream issue*)

v0.5.0
------

- `Get-VitalInformation`: Add `-WUParameters` for passing arbitrary parameters to `Get-WindowsUpdate`
- `Invoke-VitalMaintenance`: Replace `-WUTitleExclude` with `-WUParameters` for passing arbitrary parameters to `Install-WindowsUpdate` (**Breaking change**)

v0.4.7
------

- `Invoke-VitalChecks`: Split SFC output on newlines so the output is a string array

v0.4.6
------

- `Invoke-VitalChecks`: Fix SFC output under sessions without a console (e.g. WinRM)
- `Invoke-VitalChecks`: Remove extra newlines in SFC output due to `\r\r\n` sequences

v0.4.5
------

- `Invoke-VitalChecks`: Run SFC scan after component store scan as the more correct ordering
- `Invoke-VitalMaintenance`: Explicitly import `PSWindowsUpdate` module to fix PowerShell Core issue

v0.4.4
------

- `Get-VitalInformation`: Fall back to last write time of uninstall key for installed programs

v0.4.3
------

- `Invoke-VitalChecks`: Skip `ChkDsk` scan for *PortableBaseLayer* volume
- `Invoke-VitalMaintenance`: Add `-WUTitleExclude` parameter for excluding updates by title
- `Invoke-VitalMaintenance`: Add missing help information for parameters
- Apply code formatting

v0.4.2
------

- Syntax fixes for older PowerShell versions
- Performance optimisations around array use

v0.4.1
------

- Remove unneeded files from published package
- Minor documentation updates & miscellaneous fixes

v0.4.0
------

- **Breaking change**: Parameters for all functions have been reworked for more flexible task selection
- `Get-VitalInformation`: The `CrashDumps` task checks we're running with Administrator privileges
- `Get-VitalInformation`: The `InstalledFeatures` task checks if we're running on Windows Server
- `Get-VitalInformation`: The `WindowsUpdates` task checks we're running with Administrator privileges

v0.3.7
------

- `Get-VitalInformation`: Installed programs now include `PSPath` and default to a friendly table view

v0.3.6
------

- `Get-VitalInformation`: Check we're running on Windows 8/Server 2012 or newer for storage volumes summary
- `Invoke-VitalChecks`: Add exFAT to supported file systems for scanning
- `Invoke-VitalChecks`: Check we're running on Windows 8/Server 2012 or newer for file system scans
- `Invoke-VitalChecks`: Skip fix operations on FAT volumes due to lack of online repair support
- Minor documentation updates & miscellaneous code clean-up

v0.3.5
------

- Return the exception message and fail immediately if the Sysinternals download fails

v0.3.4
------

- Add PSScriptAnalyzer linting configuration

v0.3.3
------

- `Get-VitalInformation`: Use the `Version.txt` file for checking the installed Sysinternals Suite version
- `Invoke-VitalMaintenance`: Create a `Version.txt` file when installing or updating Sysinternals Suite

v0.3.2
------

- `Invoke-VitalChecks`: Capture SFC output correctly by using UTF-16 encoding
- `Invoke-VitalMaintenance`: Use the `TEMP` environment variable directly when deleting the current user's temporary files
- Minor documentation updates

v0.3.1
------

- Add built-in help for all exported functions

0.3.0
-----

- Cmdlets now default to running with all options
- Rename `Get-VitalStatistics` to `Get-VitalInformation`
- `Get-VitalInformation`: Add `-DevicesNotPresent` to retrieve devices with a status of `UNKNOWN`
- `Get-VitalInformation`: Add `-HypervisorInfo` to retrieve details on the hypervisor we're running in (if any)
- `Get-VitalInformation`: Add `-SysinternalsSuite` to retrieve version of Sysinternals Suite that's currently installed
- `Get-VitalInformation`: Change `-DevicesWithBadStatus` to only retrieves devices with a status of `ERROR` or `DEGRADED`
- `Get-VitalInformation`: Rename `-VolumeSummary` to `-StorageVolumes`
- `Get-VitalInformation`: Remove `-AllStatistics` (this is now the default when no other parameters are specified)
- `Invoke-VitalChecks`: Remove `-AllChecks` (this is now the default when no other parameters are specified)
- `Invoke-VitalMaintenance`: Add `-ClearInternetExplorerCache` to clear all cached Internet Explorer browser data
- `Invoke-VitalMaintenance`: Add `-DeleteErrorReports` to clear all error reports for the system & current user
- `Invoke-VitalMaintenance`: Add `-DeleteTemporaryFiles` to clear all temporary files for the system & current user
- `Invoke-VitalMaintenance`: Remove `-AllMaintenance` (this is now the default when no other parameters are specified)
- Enabled Strict Mode set to version 2.0 (latest at time of writing)
- Major refactoring & clean-up of the codebase to conform to best practices

v0.2.8
------

- Set `PSCustomObject` attributes to `False` to indicate a requested operation didn't run

v0.2.7
------

- Remove assumptions that we're running on 64-bit Windows (should work correctly on 32-bit)

v0.2.6
------

- Fix a stupid bug due to lack of testing that broke updating the *Sysinternals Suite* files

v0.2.5
------

- Module now supports *PowerShell 4.0* and newer (previously required *PowerShell 5.0* or newer)

v0.2.4
------

- Test for `Get-ComputerInfo` & `Get-PnpDevice` cmdlets (only available on **Windows 10** or newer)

v0.2.3
------

- Fix exception handling changes introduced in previous version to actually trigger the `Catch` block

v0.2.2
------

- Improved exception handling for `-EmptyRecycleBin` and `-PowerShellHelp` options of `Invoke-VitalMaintenance`

v0.2.1
------

- Updated the module manifest to reflect renaming of the `Invoke-VitalMaintenance` function

v0.2
----

- Cmdlets now return a suitable `PSCustomObject` with categorised output
- Add support for retrieving consolidated computer & operating system info (via `Get-ComputerInfo`)
- Add support for checking for & installing Windows updates (requires `PSWindowsUpdate` module)
- Add support for retrieving devices with a status other than 'OK' (**Windows 10/Server 2016 only**)
- Add support for checking for kernel & service profile crash dumps (`LocalSystem`, `LocalService` & `NetworkService`)
- Add support for emptying the Recycle Bin (via `Clear-RecycleBin`)
- Major clean-up of code (stylistic improvements, stop using `Write-Host`, etc...)

v0.1
----

- Initial stable release
