# PSIntegrity

[![Build status](https://ci.appveyor.com/api/projects/status/c5qvuou6jb9hyoc1?svg=true)](https://ci.appveyor.com/project/jborean93/psintegrity)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSIntegrity.svg)](https://www.powershellgallery.com/packages/PSIntegrity)

Details on the mandatory integrity mechanism can be found at
[Windows Vista Integrity Mechanism Technical Reference](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625964\(v%3dmsdn.10\))


## Info

Cmdlets included with this module are;

* [Get-IntegrityLabel](Docs/Get-IntegrityLabel.md): Gets an instance of `BaseObjectLabel` for the resource specified
* [Remove-IntegrityLabel](Docs/Remove-IntegrityLabel.md): Removes the mandatory integrity label set on an object
* [Set-IntegrityLabel](Docs/Set-IntegrityLabel.md): Adds or changes the mandatory integrity label set on an object

The `Get-IntegrityLabel` cmdlet outputs an instance of `BaseObjectLabel` which
can be used as an input to `Remove-IntegrityLabel` or `Set-IntegrityLabel`.
This object can also be used separately from the other cmdlets to manage the
integrity level label of an object if that is preferred. The docs for this
class can be found at [Docs/BaseObjectLabel](Docs/BaseObjectLabel.md).


## Requirements

These cmdlets have the following requirements

* PowerShell v3.0 or newer
* Windows PowerShell (not PowerShell Core)
* Windows Server 2008 R2/Windows 7 or newer


## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).
This is installed by default with PowerShell 5 but can be added on PowerShell
3 or 4 by installing the MSI [here](https://www.microsoft.com/en-us/download/details.aspx?id=51451).

Once installed, you can install this module by running;

```
# Install for all users
Install-Module -Name PSIntegrity

# Install for only the current user
Install-Module -Name PSIntegrity -Scope CurrentUser
```

If you wish to remove the module, just run
`Uninstall-Module -Name PSIntegrity`.

If you cannot use PowerShellGet, you can still install the module manually,
here are some basic steps on how to do this;

1. Download the latext zip from GitHub [here](https://github.com/jborean93/PSIntegrity/releases/latest)
2. Extract the zip
3. Copy the folder `PSIntegrity` inside the zip to a path that is set in `$env:PSModulePath`. By default this could be `C:\Program Files\WindowsPowerShell\Modules` or `C:\Users\<user>\Documents\WindowsPowerShell\Modules`
4. Reopen PowerShell and unblock the downloaded files with `$path = (Get-Module -Name PSPrivilege -ListAvailable).ModuleBase; Unblock-File -Path $path\*.psd1;`
5. Reopen PowerShell one more time and you can start using the cmdlets

_Note: You are not limited to installing the module to those example paths, you can add a new entry to the environment variable `PSModulePath` if you want to use another path._


## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the
changes. To test out your changes locally you can just run `.\build.ps1` in
PowerShell. This script will ensure all dependencies are installed before
running the test suite.

_Note: this requires PowerShellGet or WMF 5 to be installed_


## Backlog

* Add support for different types of objects like services, registry keys