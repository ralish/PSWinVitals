Changelog
=========

## v0.2.2

- Improved exception handling for `-EmptyRecycleBin` and `-PowerShellHelp` options of `Invoke-VitalMaintenance`

## v0.2.1

- Updated the module manifest to reflect renaming of the `Invoke-VitalMaintenance` function

## v0.2

- Cmdlets now return a suitable `PSCustomObject` with categorised output
- Add support for retrieving consolidated computer & operating system info (via `Get-ComputerInfo`)
- Add support for checking for & installing Windows updates (requires `PSWindowsUpdate` module)
- Add support for retrieving devices with a status other than 'OK' (**Windows 10/Server 2016 only**)
- Add support for checking for kernel & service profile crash dumps (`LocalSystem`, `LocalService` & `NetworkService`)
- Add support for emptying the Recycle Bin (via `Clear-RecycleBin`)
- Major clean-up of code (stylistic improvements, stop using `Write-Host`, etc...)

## v0.1

- Initial stable release