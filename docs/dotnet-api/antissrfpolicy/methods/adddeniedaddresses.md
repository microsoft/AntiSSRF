---
layout: default
title: AddDeniedAddresses
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
nav_order: 2
description: "AddDeniedAddresses method documentation"
---

# AntiSSRFPolicy.AddDeniedAddresses Method

## Definition

Adds IP networks to the deny list. Requests to any IP address that matches any of the specified networks will be blocked by the handler. Allowed addresses take precedence over denied addresses, so if an IP address matches a network on both the allow and deny list, it will be allowed.

```csharp
public void AddDeniedAddresses(string[] networks)
```

{: .note }
> `AllowedAddresses` takes precedence over `DeniedAddresses`. If an IP address matches both, it will be considered allowed by the policy.

{: .note }
> `DenyAllUnspecifiedIPs` takes precedence over `DeniedAddresses`. If `DenyAllUnspecifiedIPs` is `true`, `DeniedAddresses` will not be considered when determining if an IP address is allowed or blocked by the policy.

### Parameters

`networks`: `string[]`

The list of IPv4/IPv6 addresses or subnets to be explicitly blocked by the policy.

Networks can be:
* IPv4 addresses in dotted-quad notation
    * e.g. `127.0.0.1`
* IPv6 addresses in expanded notation `x:x:x:x:x:x:x:x`, where the `x`s are one to four hexadecimal digits
    * e.g. `ABCD:EF01:2345:6789:ABCD:EF01:2345:6789`
* IPv6 addresses in compressed notation, where one group of consecutive 0s is represented with `::`
    * e.g. `ABCD::`, `::1`, `ABCD:EF01::2345:6789`
* IPv6 in mixed notation `x:x:x:x:x:x:d.d.d.d`, where the `x`s are hexadecimal values and the `d`s are decimal
    * e.g. `::FFFF:127.0.0.1`
* Any of the above addresses with a decimal prefix length `<ip-address>/<prefix-length>` 
    * e.g. `192.0.2.0/24`, `2001:db8::/32`

### Exceptions

`ArgumentNullException`
* The `networks` parameter is `null` or contains `null` values.

`FormatException`
* A network string is not in valid CIDR format.

`AntiSSRFException`
* Attempted to edit the policy after it has been used to create a handler via `GetHandler()`.
* `DenyAllUnspecifiedIPs` is already set to `true`.
