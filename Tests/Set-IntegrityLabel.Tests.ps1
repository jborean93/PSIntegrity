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
        $temp_file = $null

        BeforeEach {
            $temp_file = [System.IO.Path]::GetTempFileName()
            # use the var in the same block to pass PSScriptAnalyzer
            $temp_file > $null
        }

        AfterEach {
            if (Test-Path -Path $temp_file) {
                Remove-Item -Path $temp_file -Force
            }
        }

        It "Sets the integrity label" {
            $current_level = Get-IntegrityLabel -Path $temp_file
            $current_level.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)

            $no_passthru = Set-IntegrityLabel -Path $temp_file -Label Low
            $no_passthru | Should -Be $null
            $current_level.Refresh()
            $current_level.Label | Should -Be ([PSIntegrity.MandatoryLabel]::Low)
            $current_level.Sid.Value | Should -Be "S-1-16-4096"

            $passthru = Set-IntegrityLabel -Path $temp_file -Label Medium -PassThru
            $passthru.Label | Should -Be ([PSIntegrity.MandatoryLabel]::Medium)
            $passthru.Sid.Value | Should -Be "S-1-16-8192"

            Set-IntegrityLabel -InputObject $passthru -Label High
            $passthru.Label | Should -Be ([PSIntegrity.MandatoryLabel]::High)
            $passthru.Sid.Value | Should -Be "S-1-16-12288"

            $passthru | Set-IntegrityLabel -Label Untrusted
            $passthru.Label | Should -Be ([PSIntegrity.MandatoryLabel]::Untrusted)
            $passthru.Sid.Value | Should -Be "S-1-16-0"

            [PSCustomObject]@{InputObject = $passthru} | Set-IntegrityLabel -Label None
            $passthru.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
            $passthru.Sid | Should -Be $null

            # Set with -WhatIf
            $passthru | Set-IntegrityLabel -Label Untrusted -WhatIf
            $passthru.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Set the integrity label flags" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -Flags "ContainerInherit", "ObjectInherit" -PassThru
            $actual.AceFlags | Should -Be ([System.Security.AccessControl.AceFlags]"ContainerInherit, ObjectInherit")

            $actual | Set-IntegrityLabel -Label Low -Flags None
            $actual.AceFlags | Should -Be ([System.Security.AccessControl.AceFlags]::None)
        }

        It "Failed to set InheritOnly integrity ace flag" {
            Set-IntegrityLabel -Path $temp_file -Label Low -Flags "InheritOnly" -ErrorAction SilentlyContinue -ErrorVariable err
            $err.Count | Should -Be 1
            $err[0].CategoryInfo.Category | Should -Be "InvalidOperation"
            $err[0].FullyQualifiedErrorId | Should -Be "InvalidOperation,PSIntegrity,Set-IntegrityLabel"
            $err[0].Exception.Message | Should -Be "Cannot set the InheritOnly AceFlags for an integrity label."

            # Verify that nothing was actually changed
            $actual = Get-IntegrityLabel -Path $temp_file
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Set the integrity access mask" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -AccessMask NoWriteUp, NoReadUp -PassThru
            $actual.AccessMask | Should -Be ([PSIntegrity.MandatoryLabelMask]"NoWriteUp, NoReadUp")

            $actual | Set-IntegrityLabel -Label Low -AccessMask None
            $actual.AccessMask | Should -Be ([PSIntegrity.MandatoryLabelMask]::None)
        }
    }
}