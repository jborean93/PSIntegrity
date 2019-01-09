# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function Remove-IntegrityLabel {
    <#
    .SYNOPSIS
    Removes an integrity label and policy from the object specified.

    .DESCRIPTION
    This cmdlet can be used to easily remove an integrity label and it's policy
    from an object. You can also use Set-IntegrityLabel -Label None to achieve
    the same thing.

    .PARAMETER InputObject
    [PSIntegrity.BaseObjectLabel] A class object that implements
    PSIntegrity.BaseObjectLabel. This can be retrieved by calling
    Get-IntegrityLabel or the return object of this cmdlet when using the
    -PassThru switch for this cmdlet. This parameter is mutually exclusive to
    Path.

    .PARAMETER Path
    [String] The path to the resource to remove the integrity level. This
    parameter is mutually exclusive to InputObject.

    .PARAMETER PassThru
    [Switch] Will output the BaseObjectLabel used when removing the label.

    .INPUTS
    [PSIntegrity.BaseObjectLabel] An object that implements
    PSIntegirty.BaseObjectLabel.

    .OUTPUTS
    None when -PassThru is not specified, otherwise an object that implements
    [PSIntegrity.BaseObjectLabel].

    .EXAMPLE
    # Remove an integrity label from a file
    Remove-IntegrityLabel -Path C:\Users\test\file.txt

    # Remove an integrity label from a file and get the label object back
    $label = Remove-IntegrityLabel -Path C:\Users\test\file.txt -PassThru

    # Remove an integrity label using InputObject
    Remove-IntegrityLabel -InputObject $label
    #>
    [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName="Path")]
    Param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,
            ParameterSetName="InputObject")]
        [PSIntegrity.BaseObjectLabel]$InputObject,
        [Parameter(Position=0, Mandatory=$true, ParameterSetName="Path")]
        [String]$Path,
        [Switch]$PassThru
    )

    if ($PSCmdlet.ParameterSetName -eq "Path") {
        $InputObject = Get-IntegrityLabel -Path $Path
    }

    if ($InputObject.Label -ne [PSIntegrity.MandatoryLabel]::None) {
        if ($PSCmdlet.ShouldProcess($InputObject.Path, "Remove Label $($InputObject.Label)")) {
            $InputObject.Label = [PSIntegrity.MandatoryLabel]::None
            $InputObject.Persist()
        }
    }

    if ($PassThru) {
        Write-Output -InputObject $InputObject
    }
}