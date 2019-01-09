# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

@{
    RootModule = 'PSIntegrity.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'e8c605f2-c571-4022-92f9-696cb36f36e5'
    Author = 'Jordan Borean'
    Copyright = 'Copyright (c) 2018 by Jordan Borean, Red Hat, licensed under MIT.'
    Description = "Adds cmdlets to add/get/remote/set the mandatory integrity level on an object.`nSee https://github.com/jborean93/PSIntegrity for more info"
    PowerShellVersion = '3.0'
    FunctionsToExport = @(
        "Get-IntegrityLabel",
        "Remove-IntegrityLabel",
        "Set-IntegrityLabel"
    )
    PrivateData = @{
        PSData = @{
            Tags = @(
                "DevOps",
                "Security",
                "Windows"
            )
            LicenseUri = 'https://github.com/jborean93/PSIntegrity/blob/master/LICENSE'
            ProjectUri = 'https://github.com/jborean93/PSIntegrity'
            ReleaseNotes = 'See https://github.com/jborean93/PSIntegrity/blob/master/CHANGELOG.md'
        }
    }
}