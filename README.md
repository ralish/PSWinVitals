PSWinVitals
===========

A PowerShell module to consolidate several common system checks, updates & statistics into simple functions.

Requirements
------------

- PowerShell 4.0 (or later)

Installing
----------

### PowerShellGet (included with PowerShell 5.0)

The latest release of the module is published to the [PowerShell Gallery](https://www.powershellgallery.com/) for installation via the [PowerShellGet module](https://www.powershellgallery.com/GettingStarted):

```posh
Install-Module -Name PSWinVitals
```

You can find the module listing [here](https://www.powershellgallery.com/packages/PSWinVitals).

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

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).