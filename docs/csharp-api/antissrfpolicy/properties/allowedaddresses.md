---
layout: default
title: AllowedAddresses
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "AllowedAddresses property documentation"
---

# AntiSSRFPolicy.AllowedAddresses Property

## Definition

Gets a read-only view of the currently allowed IP address ranges as CIDR notation strings.

```csharp
public IReadOnlyList<string> AllowedAddresses { get; }
```

{: .note }
> `AllowedAddresses` takes precedence over `DeniedAddresses`. If an IP address matches both, it will be considered allowed by the policy.

### Property Value

`IReadOnlyList<string>`

A read-only list of the allowed IP address ranges in CIDR notation.
