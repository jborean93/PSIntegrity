# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

$verbose = @{}
if ($env:APPVEYOR_REPO_BRANCH -and $env:APPVEYOR_REPO_BRANCH -notlike "master") {
    $verbose.Add("Verbose", $true)
}

$ps_version = $PSVersionTable.PSVersion.Major
$module_name = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
$repo_name = (Get-ChildItem -Path $PSScriptRoot\.. -Directory -Exclude @("Tests", "Docs")).Name
Import-Module -Name $PSScriptRoot\..\$repo_name -Force

Describe "$module_name PS$ps_version tests" {
    Context 'Strict mode' {
        Set-StrictMode -Version latest

        It "Gets the integrity label of normal file" {
            $actual = Get-IntegrityLabel -Path "$env:SystemRoot\system32\cmd.exe"
            $actual -is [PSIntegrity.FileObjectLabel] | Should -Be $true
            $actual.AceFlags | Should -Be ([System.Security.AccessControl.AceFlags ]::None)
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
            $actual.AccessMask | Should -Be ([PSIntegrity.MandatoryLabelMask]::None)
            $actual.Sid | Should -Be $null
        }

        It "Fails to get label of missing file" {
            $null = Get-IntegrityLabel -Path "C:\fake\folder" -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            $err[0].CategoryInfo.Category | Should -Be "ObjectNotFound"
            $err[0].FullyQualifiedErrorId | Should -Be "PathNotFound,PSIntegrity,Get-IntegrityLabel"
            $err[0].Exception.Message | Should -Be "Cannot find path 'C:\fake\folder' because it does not exist."
        }

        It "Set label outside of cmdlet" {
            $temp_file = [System.IO.Path]::GetTempFileName()
            try {
                $actual = Get-IntegrityLabel -Path $temp_file
                $actual.Label = [PSIntegrity.MandatoryLabel]::Low

                $actual2 = Get-IntegrityLabel -Path $temp_file
                $actual2.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
                $actual.Persist()
                $actual2.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
                $actual2.Refresh()
                $actual2.Label | Should -Be ([PSIntegrity.MandatoryLabel]::Low)
            } finally {
                Remove-Item -Path $temp_file -Force
            }
        }
    }
}