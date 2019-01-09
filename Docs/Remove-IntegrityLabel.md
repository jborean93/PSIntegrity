# Remove-IntegrityLabel

Removes the integrity label from an object.

## Syntax

```
Remove-IntegrityLabel
    -Path <String>
    [<CommonParameters>]

Remove-IntegrityLabel
    -InputObject <PSIntegrity.BaseObjectLabel>
    [<CommonParameters>]
```

## Parameters

* `Path`: The path to the file to remove the integrity label on. This is mutually exclusive to `InputObject`.
* `InputObject`: The PSIntegrity.BaseObjectLabel object to remove the integrity label on. This is mutually exclusive to `Path`.

## Optional Parameters

None

## Input

* `<PSIntegrity.BaseObjectLabel>`: The object can be passed as a pipeline input of the `InputObject` parameter

## Output

No object is outputted unless `-PassThru` is specified then

* `<PSIntegrity.BaseObjectLabel>`: A object that implements `BaseObjectLabel`

## Examples

```ps
# Remove an integrity label from a file
Remove-IntegrityLabel -Path C:\Users\test\file.txt

# Remove an integrity label from a file and get the label object back
$label = Remove-IntegrityLabel -Path C:\Users\test\file.txt -PassThru

# Remove an integrity label using InputObject
Remove-IntegrityLabel -InputObject $label
```