# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function Set-IntegrityLabel {
    <#
    .SYNOPSIS
    Sets the mandatory integrity level ACE for a resource.

    .DESCRIPTION
    This cmdlet can be used to set the mandatory integrity level ACE of a
    resource as well as the AceFlags and AccessMask for that ACE.

    .PARAMETER InputObject
    [PSIntegrity.BaseObjectLabel] A class object that implements
    PSIntegrity.BaseObjectLabel. This can be retrieved by calling
    Get-IntegrityLabel or the return object of this cmdlet when using the
    -PassThru switch for this cmdlet. This parameter is mutually exclusive to
    Path.

    .PARAMETER Path
    [String] The path to the resource to set the integrity level. This
    parameter is mutually exclusive to InputObject.

    .PARAMETER Label
    [PSIntegrity.MandatoryLabel] The label to set on the resource. Use None to
    remove a label (or the Remove-IntegrityLabel cmdlet). The Unknown label
    cannot be set as it is only used if an unknown label has been set by
    another tool. You can also only set a label that is equal to or less than
    the current process's label which is typicaly Medium for a standard process
    or High for an admin process. To set a high label you will need the
    SeRelabelPrivilege privilege on the running account.

    .PARAMETER Flags
    [System.Security.AccessControl.AceFlags] Sets the AceFlags for the label
    ACE. These flags control the inheritance and auditing behaviour of the ACE.
    You cannot set the InheritOnly flag for a label ACE.

    .PARAMETER AccessMask
    [PSIntegrity.MandatoryLabelMask] Set the access mask for the label which
    controls the label policy set on the resource. Set to None to remove the
    access mask.

    .PARAMETER PassThru
    [Switch] Will output the BaseObjectLabel used to set the label.

    .INPUTS
    [PSIntegrity.BaseObjectLabel] An object that implements
    PSIntegirty.BaseObjectLabel.

    .OUTPUTS
    None when -PassThru is not specified, otherwise an object that implements
    [PSIntegrity.BaseObjectLabel].

    .EXAMPLE
    # Set a High integrity label to a file
    Set-IntegrityLabel -Path C:\Users\test\file.txt -Label High

    # Set a High integrity label to Low and get the label object back
    $label = Set-IntegrityLabel -Path C:\Users\test\file.txt -Label Low -PassThru

    # Remove an integrity label using InputObject
    Set-IntegrityLabel -InputObject $label -Label None

    # Set no write/read/execute policy for the label
    $label | Set-IntegrityLabel -Label High -AccessMask NoWriteUp, NoReadUp, NoExecuteUp

    # Ensure the label is inherited to all child folders and files
    Set-IntegrityLabel -Path C:\application -Label Low -Flags ContainerInherit, ObjectInherit

    .NOTES
    You cannot set a label that is higher than the one on the current access
    token unless the user has the SeRelabelPrivilege enabled
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/modify-an-object-label.
    #>
    [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName="Path")]
    Param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,
            ParameterSetName="InputObject")]
        [PSIntegrity.BaseObjectLabel]$InputObject,
        [Parameter(Position=0, Mandatory=$true, ParameterSetName="Path")]
        [String]$Path,
        [Parameter(Position=1, Mandatory=$true)]
        [PSIntegrity.MandatoryLabel]$Label,
        [System.Security.AccessControl.AceFlags]$Flags,
        [PSIntegrity.MandatoryLabelMask]$AccessMask,
        [Switch]$PassThru
    )

    if ($PSCmdlet.ParameterSetName -eq "Path") {
        $InputObject = Get-IntegrityLabel -Path $Path
    }

    $changes = [System.Collections.Generic.List`1[String]]@()
    if ($null -ne $Flags -and $Flags -ne $InputObject.AceFlags) {
        if ($Flags.HasFlag([System.Security.AccessControl.AceFlags]::InheritOnly)) {
            $error_args = @{
                Message = "Cannot set the InheritOnly AceFlags for an integrity label."
                Category = "InvalidOperation"
                ErrorId = "InvalidOperation,PSIntegrity"
                CategoryReason = "ArgumentException"
                CategoryTargetName = $Flags
                CategoryTargetType = $Flags.GetType().FullName
            }
            Write-Error @error_args
            return
        }

        $change = "AceFlags from $($InputObject.AceFlags) to $Flags"
        Write-Verbose -Message "Changing $change"
        $InputObject.AceFlags = $Flags
        $changes.Add($change) > $null
    }

    if ($InputObject.Label -ne $Label) {
        $change = "Label from $($InputObject.Label) to $Label"
        Write-Verbose -Message "Changing $change"
        $InputObject.Label = $Label
        $changes.Add($change) > $null
    }

    if ($null -ne $AccessMask -and $AccessMask -ne $InputObject.AccessMask) {
        $change = "AcessMask from $($InputObject.AccessMask) to $AccessMask"
        Write-Verbose -Message "Changing $change"
        $InputObject.AccessMask = $AccessMask
        $changes.Add($change) > $null
    }

    if ($changes.Count -gt 0) {
        if ($PSCmdlet.ShouldProcess($InputObject.Path, "Persist changes to object: $($changes -join ", ")")) {
            $InputObject.Persist()
        } else {
            # If we don't do the ACE change, we refresh to get the original values back
            $InputObject.Refresh()
        }   
    }

    if ($PassThru) {
        Write-Output -InputObject $InputObject
    }
}