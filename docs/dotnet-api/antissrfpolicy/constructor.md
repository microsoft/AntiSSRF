---
layout: default
title: Constructor
parent: AntiSSRFPolicy (C#)
grand_parent: C# API Reference
nav_order: 1
description: "AntiSSRFPolicy constructor documentation"
---

# AntiSSRFPolicy Constructor

## Definition

Initializes a new instance of the `AntiSSRFPolicy` class with the specified initial configuration.

```csharp
public AntiSSRFPolicy(PolicyConfigOptions config)
```

### Parameters

`config`: `PolicyConfigOptions`

* `PolicyConfigOptions.InternalOnly`
* `PolicyConfigOptions.ExternalOnlyV1`
* `PolicyConfigOptions.ExternalOnlyLatest`
* `PolicyConfigOptions.None`

### Exceptions

`ArgumentOutOfRangeException`
Thrown when an invalid `PolicyConfigOptions` value is provided.

### PolicyConfigOptions.InternalOnly

Recommended when:
* The policy should enforce requests only reach internal addresses, blocking all requests to external addresses.
* **OR** the policy should enforce requests only reach addresses specified by `AddAllowedAddresses`.

Configuration:
* Sets `DenyAllUnspecifiedIPs` to `true`, blocking all requests to all IP addresses by default, only allowing requests to IP addresses that have been explicitly specified by `AddAllowedAddresses`.

### PolicyConfigOptions.ExternalOnlyV1

Recommended when:
* The policy should enforce that requests should not reach any internal or special-purpose address, unless otherwise specified by `AddAllowedAddresses`.

Configuration:
* Blocks all requests to internal and special-purpose addresses as specified by `IPAddressRanges.recommendedV1`. This excludes any address ranges that have been explicitly specified by `AddAllowedAddresses`.
* Sets `AddXFFHeader` to `true` on all outgoing requests that do not already have the header. This can be disabled with `policy.AddXFFHeader = false`.

### PolicyConfigOptions.ExternalOnlyLatest

{: .important }
> This policy does NOT follow semantic versioning. It will always stay up-to-date with the latest recommended addresses with no code changes required by the user.

Recommended when:
* Currently the same as `PolicyConfigOptions.ExternalOnlyV1`, if you want your security requirements updated automatically and are okay with changes that are not reflected in the package's semantic version.

Configuration:
* Currently the same as `PolicyConfigOptions.ExternalOnlyV1`.

### PolicyConfigOptions.None

Recommended when:
* You plan to manually configure all policy customizations.

Configuration:
* Unless customized, this policy will not update any requests and will not block any requests.

### Security Notes

To prevent SSRF vulnerabilities, it is a best practice to ensure that your code can make requests to external endpoints or to internal endpoints, but never both.

If your service needs to make outbound requests to external endpoints, you need to make sure that it can't be used to access internal endpoints as well. In this case, we recommend using `PolicyConfigOptions.ExternalOnlyLatest`, which takes care of blocking internal and special-purpose addresses automatically.

If your service needs to make outbound requests to internal endpoints, you need to make sure that it can't be used to access external endpoints as well. In this case, we recommend using `PolicyConfigOptions.InternalOnly` to block all unspecified addresses, then use `AddAllowedAddresses(...)` with the specific internal IP addresses that your service might need to access.

For more about the `X-Forwarded-For` header, see [AddXFFHeader](properties/addxffheader.html).

### Immutability After Handler Creation

{: .warning }
> Once `GetHandler()` is called, the policy becomes immutable. Any attempt to change properties or call customization methods will throw an `AntiSSRFException`.
