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

        It "Removes the integrity label by path" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            $output = Remove-IntegrityLabel -Path $temp_file
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
            $output | Should -Be $null

            # Test it again
            Remove-IntegrityLabel -Path $temp_file
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Removes the integrity label by path with PassThru" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            $output = Remove-IntegrityLabel -Path $temp_file -PassThru
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
            $output.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Removes the integrity label by input object" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            Remove-IntegrityLabel -InputObject $actual
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Removes the integrity label by pipeline input" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            $actual | Remove-IntegrityLabel
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Removes the integrity label by pipeline input by name" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            [PSCustomObject]@{InputObject=$actual} | Remove-IntegrityLabel
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::None)
        }

        It "Removes the integrity label with WhatIf" {
            $actual = Set-IntegrityLabel -Path $temp_file -Label Low -PassThru
            $output = Remove-IntegrityLabel -Path $temp_file -WhatIf
            $actual.Refresh()
            $actual.Label | Should -Be ([PSIntegrity.MandatoryLabel]::Low)
            $output | Should -Be $null
        }
    }
}