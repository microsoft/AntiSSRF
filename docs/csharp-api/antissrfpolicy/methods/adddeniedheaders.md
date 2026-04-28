---
layout: default
title: AddDeniedHeaders
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
nav_order: 4
description: "AddDeniedHeaders method documentation"
---

# AntiSSRFPolicy.AddDeniedHeaders Method

## Definition

Adds headers to the list of denied headers. HTTP requests containing any of these headers will be blocked by the handler.

```csharp
public void AddDeniedHeaders(string[] deniedHeaders)
```

{: .note }
> Both `RequiredHeaders` and `DeniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`deniedHeaders`: `string[]`

The list of headers for the policy to block.

### Exceptions

`ArgumentNullException`
* The `deniedHeaders` parameter is `null` or contains `null` values.

`ArgumentException`
* A header name is empty or whitespace.

`AntiSSRFException`
* Attempted to edit the policy after it has been used to create a handler via `GetHandler()`.
