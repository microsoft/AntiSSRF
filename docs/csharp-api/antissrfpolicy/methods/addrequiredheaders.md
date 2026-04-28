---
layout: default
title: AddRequiredHeaders
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
nav_order: 3
description: "AddRequiredHeaders method documentation"
---

# AntiSSRFPolicy.AddRequiredHeaders Method

## Definition

Adds headers to the list of required headers. HTTP requests missing any of these headers will be blocked by the handler.

```csharp
public void AddRequiredHeaders(string[] requiredHeaders)
```

{: .note }
> Both `RequiredHeaders` and `DeniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`requiredHeaders`: `string[]`

The list of headers for the policy to require.

### Exceptions

`ArgumentNullException`
* The `requiredHeaders` parameter is `null` or contains `null` values.

`ArgumentException`
* A header name is empty or whitespace.

`AntiSSRFException`
* Attempted to edit the policy after it has been used to create a handler via `GetHandler()`.
