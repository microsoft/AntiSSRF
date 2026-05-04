---
layout: default
title: RequiredHeaders
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "RequiredHeaders property documentation"
---

# AntiSSRFPolicy.RequiredHeaders Property

## Definition

Gets a read-only view of the currently required headers. HTTP requests missing any of these headers will be blocked by the handler.

```csharp
public IReadOnlyList<string> RequiredHeaders { get; }
```

{: .note }
> Both `RequiredHeaders` and `DeniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`IReadOnlyList<string>`

A read-only list of the headers explicitly required by the policy.
