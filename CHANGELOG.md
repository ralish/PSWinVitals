Changelog
=========

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
