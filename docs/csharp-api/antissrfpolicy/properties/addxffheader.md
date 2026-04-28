---
layout: default
title: AddXFFHeader
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "AddXFFHeader property documentation"
---

# AntiSSRFPolicy.AddXFFHeader Property

## Definition

Gets or sets whether the handler should add an `X-Forwarded-For: true` header to outgoing HTTP requests that are missing the header.

{: .important }
> The header is added with the dummy value `"true"`. If your end service requires this header to be a valid IP address, you will have to add the header manually.

```csharp
public bool AddXFFHeader { get; set; }
```

### Property Value

`bool`

* `true` if the `X-Forwarded-For` header should be added to requests where it is missing.
* `false` if the `X-Forwarded-For` header should not be added.

Default: `false` (unless using `ExternalOnlyV1` or `ExternalOnlyLatest`, which set it to `true`)

### Exceptions

`AntiSSRFException`
Thrown when attempting to change the property after the policy has been used to create a handler via `GetHandler()`.

### Security Notes

The `X-Forwarded-For` header can be an important defense-in-depth strategy against SSRF vulnerabilities. Some services, including IMDS, will drop all incoming requests with the `X-Forwarded-For` header present. By ensuring that the header is added to all outgoing requests, your service can be sure that it will never have an SSRF vulnerability that leaks data from IMDS.
