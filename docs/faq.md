---
layout: default
title: FAQ
nav_order: 5
description: "Frequently asked questions about AntiSSRF"
---

# Frequently Asked Questions

## What IP addresses or subnets should my service block?

It is important to separate HTTP clients intented for internal vs. external requests.

Ideally, for internal requests or if the range of possible IP addresses is known, use the configuration [`PolicyConfigOptions.InternalOnly`](../dotnet-api/antissrfpolicy/constructor#policyconfigoptionsinternalonly) and ONLY allow the expected ranges.

For external requests, your service should AT LEAST block the internal and special-use IP addresses, included to the configuration [`IPAddressRanges.recommendedLatest`](../ipaddressranges#recommended-ranges-latest).

## Does the AntiSSRF library support IPv6 functionality?

Yes, the AntiSSRF Library supports IPv6 functionality.

## My outgoing requests are being dropped at the destination because of an invalid X-Forwarded-For header. What should I do?

By default, the external-only configurations of AntiSSRF automatically add an `X-Forwarded-For: "true"` header to outgoing requests that don't already have this header. This is an important security feature that helps protect against access to sensitive, internal endpoints like IMDS which safely drop all requests with the `X-Forwarded-For` header.

However, some destination services may reject requests with this dummy value. If your destination service is rejecting requests because of the `X-Forwarded-For: "true"` header, you can disable this behavior:

```cs
const policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalLatest);
policy.addXFFHeader = false; // Disables automatic X-Forwarded-For header addition
```

**Important:** Only disable this feature if you are absolutely certain that:
* Your destination service drops ALL requests with the `X-Forwarded-For` header. For example, you are intentionally accessing IMDS while blocking all external IP addresses.
* **OR** another component in your service stack reliably adds the `X-Forwarded-For` header to all outgoing requests. That way, the policy does not need to add the invalid dummy value to include the header.

For more information, see the [X-Forwarded-For header documentation](../dotnet-api/antissrfpolicy/properties/addxffheader#security-notes) and [`addXFFHeader` property](../dotnet-api/antissrfpolicy/properties/addxffheader).

## What languages and frameworks are supported?

| Language | Documentation | Notes |
| --- | --- | --- |
| C# | [AntiSSRF .NET Library](dotnet-api/) | For web clients using `HttpClient` objects |
| JavaScript/TypeScript | [AntiSSRF Node.js Library](nodejs-api/) | For requests using NodeJS HTTP(S) Agents |

Broader platform support is under development.
