---
layout: default
title: DeniedHeaders
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "DeniedHeaders property documentation"
---

# AntiSSRFPolicy.DeniedHeaders Property

## Definition

Gets a read-only view of the currently denied headers. HTTP requests containing any of these headers will be blocked by the handler.

```csharp
public IReadOnlyList<string> DeniedHeaders { get; }
```

{: .note }
> Both `RequiredHeaders` and `DeniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`IReadOnlyList<string>`

A read-only list of the headers explicitly blocked by the policy.
