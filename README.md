PSWinVitals
===========

[![pwsh ver](https://img.shields.io/powershellgallery/v/PSWinVitals)](https://www.powershellgallery.com/packages/PSWinVitals)
[![pwsh dl](https://img.shields.io/powershellgallery/dt/PSWinVitals)](https://www.powershellgallery.com/packages/PSWinVitals)
[![license](https://img.shields.io/github/license/ralish/PSWinVitals)](https://choosealicense.com/licenses/mit/)

A PowerShell module to consolidate common system health checks, maintenance tasks & inventory retrieval.

- [Requirements](#requirements)
- [Installing](#installing)
- [Usage](#usage)
- [License](#license)

Requirements
------------

- PowerShell 4.0 (or later)

Installing
----------

### PowerShellGet (included with PowerShell 5.0)

The module is published to the [PowerShell Gallery](https://www.powershellgallery.com/packages/PSWinVitals):

```posh
Install-Module -Name PSWinVitals
```

### ZIP File

Download the [ZIP file](https://github.com/ralish/PSWinVitals/archive/stable.zip) of the latest release and unpack it to one of the following locations:

- Current user: `C:\Users\<your.account>\Documents\WindowsPowerShell\Modules\PSWinVitals`
- All users: `C:\Program Files\WindowsPowerShell\Modules\PSWinVitals`

### Git Clone

You can also clone the repository into one of the above locations if you'd like the ability to easily update it via Git.

### Did it work?

You can check that PowerShell is able to locate the module by running the following at a PowerShell prompt:

```posh
Get-Module PSWinVitals -ListAvailable
```

Usage
-----

The module exports three functions which handle inventory retrieval, health checks, and maintenance tasks respectively. Each function returns a `PSCustomObject` with the results of the command. A summary of the capabilities of each command follows, however, please consult the built-in help of each function for comprehensive details.

### Get-VitalInformation

- Retrieval of computer & operating system info
- Retrieval of hypervisor details (if present)
- Retrieval of hardware devices with errors
- Retrieval of hardware devices which are absent
- Retrieval of fixed storage volume details
- Check for kernel, service, or user crash dumps
- Analysis of the Windows component store
- Retrieval of installed Windows features (Server SKUs only)
- Retrieval of installed programs
- Retrieval of environment variables
- Retrieval of available Windows updates
- Retrieval of installed Sysinternals version

### Invoke-VitalChecks

- Run file system scans against all fixed volumes
- Run Windows component store scan
- Run Windows System File Checker (SFC)

### Invoke-VitalMaintenance

- Install all available Windows updates
- Perform Windows component store clean-up
- Update help for all PowerShell modules
- Install latest Sysinternals Suite tools
- Clear Internet Explorer cache
- Delete Windows Error Report files
- Delete temporary files
- Empty Recycle Bin

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
