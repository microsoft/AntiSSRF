---
layout: default
title: DenyAllUnspecifiedIPs
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "DenyAllUnspecifiedIPs property documentation"
---

# AntiSSRFPolicy.DenyAllUnspecifiedIPs Property

## Definition

Gets or sets whether the handler should deny all unspecified IP addresses. If `true`, any request to an IP address not explicitly allowed will be blocked.
To allow specific addresses, use `AddAllowedAddresses`.

```csharp
public bool DenyAllUnspecifiedIPs { get; set; }
```

### Property Value

`bool`

* `true` if all IP addresses NOT specified by `AddAllowedAddresses` should be blocked.
* `false` if only addresses in `DeniedAddresses` should be blocked.

Default: `false` (unless using `InternalOnly`, which sets it to `true`)

### Exceptions

`AntiSSRFException`
Thrown when attempting to change the property after the policy has been used to create a handler via `GetHandler()`.
