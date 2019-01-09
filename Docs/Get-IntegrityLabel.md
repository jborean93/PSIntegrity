# Get-IntegrityLabel

Gets a [PSIntegrity.BaseObjectLabel](BaseObjectLabel.md) object that can be used to get and
manipulate the integrity level of an object.

## Syntax

```
Get-IntegrityLabel
    -Path <String>
    [<CommonParameters>]
```

## Parameters

* `Path`: The path to the file to get the integrity label for

## Optional Parameters

None

## Input

* `<String>`: A string can be passed as a pipeline input of the `Path` parameter

## Output

* `<PSIntegrity.BaseObjectLabel>`: A object that implements `BaseObjectLabel`

## Examples

```ps
# Get the integrity label for a folder
Get-IntegrityLabel -Path C:\Windows
```