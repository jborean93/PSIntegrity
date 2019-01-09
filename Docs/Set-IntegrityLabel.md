# Set-IntegrityLabel

Sets the integrity label, policy and flags on an object.

## Syntax

```
Set-IntegrityLabel
    -Path <String>
    -Label <PSIntegrity.MandatoryLabel>
    [-Flags <System.Security.AccessControl.AceFlags>]
    [-AccessMask <PSIntegrity.MandatoryLabelMask>]
    [<CommonParameters>]

Set-IntegrityLabel
    -InputObject <PSIntegrity.BaseObjectLabel>
    -Label <PSIntegrity.MandatoryLabel>
    [-Flags <System.Security.AccessControl.AceFlags>]
    [-AccessMask <PSIntegrity.MandatoryLabelMask>]
    [<CommonParameters>]
```

## Parameters

* `Path`: The path to the file to set the integrity label on. This is mutually exclusive to `InputObject`.
* `InputObject`: The PSIntegrity.BaseObjectLabel object to set the integrity label on. This is mutually exclusive to `Path`.
* `Label`: The label to set on the object.

## Optional Parameters

* `Flags`: The AceFlags to set on the label.
* `AccessMask`: The access mask or policy to set on the label.

## Input

* `<PSIntegrity.BaseObjectLabel>`: The object can be passed as a pipeline input of the `InputObject` parameter

## Output

No object is outputted unless `-PassThru` is specified then

* `<PSIntegrity.BaseObjectLabel>`: A object that implements `BaseObjectLabel`

## Examples

```ps
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
```