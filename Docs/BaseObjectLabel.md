# BaseObjectLabel

This is a .NET class that is used by this module to interact with the mandatory
integrity label of a resource. `BaseObjectLabel` is the abstract class that is
implemented by other classes based on a specific resource type. The following
resource types have been defined and thereforce can be used by this module to
manage the integrity label;

* `PSIntegrity.FileObjectLabel`: Manage the integrity level on a file based resource like a file or directory

Each class that implements `PSIntegrity.BaseObjectLabel` implements a method
that returns a handle to the object based on the path specified.

## Properties

| Name       | Type                                         | Read Only | Description                                                                |
| ---------- | -------------------------------------------- | --------- | -------------------------------------------------------------------------- |
| AceFlags   | System.Security.AccessControl.AceFlags       | No        | Specifies the inheritance and auditing behaviour of the Label ACE          |
| Label      | PSIntegrity.MandatoryLabel                   | No        | Specifies the mandatory integrity label set on the object                  |
| AccessMask | PSIntegrity.MandatoryLabelMask               | No        | Specifies the behaviour of the mandatory integrity label set on the object |
| Sid        | System.Security.Principal.SecurityIdentifier | Yes       | Specifies the SID representation of the integrity label                    |

The `[System.Security.AccessControl.AceFlags]::InheritOnly` is not a valid flag
that can be set on a Mandatory Label ACE.

### PSIntegrity.MandatoryLabel

This is an enum value that can be one of the following;

* `None`: No label has been set on the object, set `Label` to this value to remove a label
* `Untrusted`: The untrusted label (`S-1-16-0`)
* `Low`: The low label (`S-1-16-4096`)
* `Medium`: The medium label (`S-1-16-8192`)
* `High`: The high label (`S-1-16-1228`)
* `System`: The system label (`S-1-16-16384`)
* `ProtectedProcess`: The protected process label (`S-1-16-16384`)
* `SecureProcess`: The secure process label (`S-1-16-28672`)
* `Unknown`: An unknown label, use the `Sid` property to get the SecurityIdentifier. You cannot set an `Unknown` label onto an object

### PSIntegrity.MandatoryLabelMask

This is an enum flags value that can be none, one, or multiple of the
following;

* `None`: The label has been set but no policy is applied
* `NoWriteUp`: A principal with a lower mandatory level than the object cannot write to the object
* `NoReadUp`: A principal with a lower mandatory level than the object cannot read the object
* `NoExecuteUp`: A principal with a lower mandatory level than the object cannot execute the object

## Methods

### Refresh()

Refreshes the integrity label info on an existing object.

#### Returns

void

### Persist()

Persists any attribute changes set on the object to the underlying resource.

#### Returns

void
