# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function Get-IntegrityLabel {
    <#
    .SYNOPSIS
    Gets the integrity label and policy for the object specified.

    .DESCRIPTION
    This cmdlet can be used to get the integrity label information for a file
    or folder. The output object can be used as the input to Set-IntegrityLabel
    and Remove-IntegrityLabel. You can also manually manipulate the label,
    policy and the flags on the object itself.

    .PARAMETER Path
    [String] The path to the resource to get the label info for.

    .INPUTS
    [String] The path to get the label for.

    .OUTPUTS
    [PSIntegrity.BaseObjectLabel] An object that implements the BaseObjectLabel
    class. This object can be used as the input to Set-IntegrityLabel and
    Remove-IntegrityLabel or even used directly to manage the label, policy,
    and flags on the object.

    .EXAMPLE
    # Get the integrity label for a folder
    Get-IntegrityLabel -Path C:\Windows

    .NOTES
    Currently only a file system object is supported by this cmdlet.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true)]
        [String]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $error_args = @{
            Message = "Cannot find path '$Path' because it does not exist."
            Category = "ObjectNotFound"
            ErrorId = "PathNotFound,PSIntegrity"
            CategoryReason = "ItemNotFoundException"
            CategoryTargetName = $Path
            CategoryTargetType = $Path.GetType().FullName
        }
        Write-Error @error_args
        return
    }

    return New-Object -TypeName PSIntegrity.FileObjectLabel -ArgumentList $Path
}