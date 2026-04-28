---
layout: default
title: GetHandler
parent: Methods
grand_parent: AntiSSRFPolicy (C#)
great_grand_parent: C# API Reference
nav_order: 5
description: "GetHandler method documentation"
---

# AntiSSRFPolicy.GetHandler Method

## Definition

Creates and returns a new `AntiSSRFHandler` instance based on the current policy configuration.

```csharp
public AntiSSRFHandler GetHandler()
```

{: .warning }
> After calling `GetHandler()`, the policy becomes immutable. Any attempt to change properties or call customization methods will throw an `AntiSSRFException`.

### Returns

`AntiSSRFHandler`

A new `AntiSSRFHandler` instance that enforces this policy. Use this handler when constructing an `HttpClient`.

### Example

```csharp
using Microsoft.Security.AntiSSRF;
using System.Net.Http;

var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);

// Customize before getting handler
policy.AddAllowedAddresses(new[] { "10.0.1.0/24" });

// Get the handler — policy is now locked
using var handler = policy.GetHandler();
using var client = new HttpClient(handler);
```
