# Generic module deployment.
#
# ASSUMPTIONS:
#
# * folder structure either like:
#
#   - RepoFolder
#     - This PSDeploy file
#     - ModuleName
#       - ModuleName.psd1
#
#   OR the less preferable:
#   - RepoFolder
#     - RepoFolder.psd1
#
# * Nuget key in $ENV:NugetApiKey
#
# * Set-BuildEnvironment from BuildHelpers module has populated ENV:BHPSModulePath and related variables

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "", Justification="Required in PSDeploy, cannot output to a stream")]
param()

Function Get-ModuleCode {
    param(
        [Parameter(Mandatory=$true)][String]$ModulePath
    )
    $module_code = Get-Content -LiteralPath $ModulePath

    # Find out where the first copyright lines end, this is the first line that
    # does not start with # and is not a blank line
    for ($i = 0; $i -lt $module_code.Length; $i++) {
        $module_line = $module_code[$i]
        if (-not ($module_line.StartsWith("#") -or $module_line -eq "")) {
            break
        }
    }

    $module_code = ($module_code | Select-Object -Skip $i) -join [System.Environment]::NewLIne
    return $module_code + [System.Environment]::NewLine
}

Function Optimize-Project {
    param([String]$Path)

    $repo_name = (Get-ChildItem -Path $Path -Directory -Exclude @("Tests", "Docs")).Name
    $module_path = Join-Path -Path $Path -ChildPath $repo_name
    if (-not (Test-Path -LiteralPath $module_path -PathType Container)) {
        Write-Error -Message "Failed to find the module at the expected path '$module_path'"
        return
    }

    # Build the initial manifest file and get the current export signature
    $manifest_file_path = Join-Path -Path $module_path -ChildPath "$($repo_name).psm1"
    if (-not (Test-Path -LiteralPath $manifest_file_path -PathType Leaf)) {
        Write-Error -Message "Failed to find the module's psm1 file at the expected path '$manifest_file_path'"
        return
    }
    $manifest_file_lines = Get-Content -Path $manifest_file_path
    $manifest_new_lines = [System.Collections.Generic.List`1[String]]@()
    foreach ($manifest_file_line in $manifest_file_lines) {
        if ($manifest_file_line -eq "### TEMPLATED EXPORT FUNCTIONS ###") {
            break
        }

        $manifest_new_lines.Add($manifest_file_line) > $null
    }
    $manifest_file = $manifest_new_lines -join [System.Environment]::NewLine

    # Read each public and private function and add it to the manifest template
    $private_functions_path = Join-Path -Path $module_path -ChildPath Private
    if (Test-Path -LiteralPath $private_functions_path) {
        $private_modules = @( Get-ChildItem -Path $private_functions_path\*.ps1 -ErrorAction SilentlyContinue )

        foreach ($private_module in $private_modules) {
            $module_code = Get-ModuleCode -ModulePath $private_module.FullName
            $manifest_file += $module_code + [System.Environment]::NewLine
        }
    }

    $public_module_names = [System.Collections.Generic.List`1[String]]@()
    $public_functions_path = Join-Path -Path $module_path -ChildPath Public
    if (Test-Path -LiteralPath $public_functions_path) {
        $public_modules = @( Get-ChildItem -Path $public_functions_path\*.ps1 -ErrorAction SilentlyContinue )

        foreach ($public_module in $public_modules) {
            $public_module_names.Add($public_module.BaseName) > $null
            $module_code = Get-ModuleCode -ModulePath $public_module.FullName
            $manifest_file += $module_code + [System.Environment]::NewLine
        }
    }

    # Now build the new export signature based on the original
    $original_signature = $manifest_file_lines | Where-Object { $_.StartsWith("Export-ModuleMember") }
    $sb_ast = [System.Management.Automation.Language.Parser]::ParseInput($original_signature, [ref]$null, [ref]$null)
    $sb_ast.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) | ForEach-Object {
        # Find the index where -Function is defined
        for ($i = 0; $i -lt $_.CommandElements.Count; $i++) {
            if ($_.CommandElements[$i].ParameterName -eq "Function") {
                break
            }
        }

        # Get the original value for the -Function parameter
        $function_value = $_.CommandElements[$i + 1].Extent.Text

        # Replace the original -Function <value> with our new one
        $new_signature = $original_signature.Replace("-Function $function_value", "-Function $($public_module_names -join ", ")")
        $manifest_file += $new_signature
    }

    # Now replace the manifest file with our new copy and remove the public and private folders
    if (Test-Path -LiteralPath $private_functions_path) {
        Remove-Item -LiteralPath $private_functions_path -Force -Recurse
    }
    if (Test-Path -LiteralPath $public_functions_path) {
        Remove-Item -LiteralPath $public_functions_path -Force -Recurse
    }
    Set-Content -LiteralPath $manifest_file_path -Value $manifest_file

    return $module_path
}

# Do nothing if the env variable is not set
if (-not $env:BHProjectPath) {
    return
}

# Create dir to store a copy of the build artifact
$build_path = Join-Path -Path $env:BHProjectPath -ChildPath "Build"
if (Test-Path -Path $build_path) {
    Remove-Item -Path $build_path -Force -Recurse
}
New-Item -Path $build_path -ItemType Directory > $null
Copy-Item -Path $env:BHModulePath -Destination $build_path -Recurse
$module_path = Optimize-Project -Path $build_path

# Verify we can import the module
Import-Module -Name $module_path

# Publish to gallery with a few restrictions
if ($env:BHBuildSystem -ne 'Unknown' -and
    $env:BHBranchName -eq "master" -and
    $env:APPVEYOR_REPO_TAG -eq "true") {

    Deploy Module {
        By PSGalleryModule {
            FromSource $module_path
            To PSGallery
            WithOptions @{
                ApiKey = $ENV:NugetApiKey
                SourceIsAbsolute = $true
            }
        }
    }
} else {
    "Skipping deployment: To deploy, ensure that...`n" +
    "`t* You are in a known build system (Current: $ENV:BHBuildSystem)`n" +
    "`t* You are committing to the master branch (Current: $ENV:BHBranchName) `n" +
    "`t* The commit is a tagged release from github with APPVEYOR_REPO_TAG=true (Current: $ENV:APPVEYOR_REPO_TAG)" | Write-Host
}

# Publish to AppVeyor if we're in AppVeyor
if($env:BHBuildSystem -eq 'AppVeyor') {
    Deploy DeveloperBuild {
        By AppVeyorModule {
            FromSource $module_path
            To AppVeyor
            WithOptions @{
                SourceIsAbsolute = $true
                Version = $env:APPVEYOR_BUILD_VERSION
            }
        }
    }
}
