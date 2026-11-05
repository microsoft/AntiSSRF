---
layout: default
title: FAQ
nav_order: 5
description: "Frequently asked questions about AntiSSRF"
---

# Frequently Asked Questions

## Onboarding

### Should Microsoft services be onboarding to this library?

If you are a Microsoft service with public code, YES! This is the Microsoft-recommended solution for mitigating SSRF vulnerabilities in Microsoft services.

If you are a Microsoft internal service, we have a separate version of the library for you. Please search for the internal version of the library or reach out to us at [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com) for help!

### What languages and frameworks are supported?

{% include supported_language.md %}

Broader platform support is under development.

## Security Behavior

### Does the AntiSSRF library support IPv6 functionality?

Yes, all the AntiSSRF libraries support IPv6 functionality as well as proper conversions with IPv4-mapped IPv6 address mappings. Other IPv4-IPv6 translation mechanisms are not natively supported, and the associated ranges are blocked by default.

### Does the library provide protections on redirects?

The `AntiSSRFPolicy` and its handlers, agents, and sessions DO re-evaluate all policy requirements for every redirect.

The `URIValidator` methods DO NOT apply protections on redirects. When using `InAzureKeyVaultDomain` or `InAzureStorageDomain`, this is okay, since they limit to only well-known, safe domains. When using `InDomain`, the lack of protections on redirects is part of the reason you must be sure that the `trustedDomains` argument truly only includes trusted domains.

### Does the library provide protections against DNS-rebinding based attacks?

The `AntiSSRFPolicy` and its handlers, agents, and sessions DO provide protections against DNS-rebinding based attacks. The IP address that is validated by the policy is EXACTLY the IP address used in the request, eliminating the potential TOCTOU problem.

The `URIValidator` methods DO NOT provide any protections for DNS-based attacks at all. This is okay for `InAzureKeyVaultDomain` and `InAzureStorageDomain`, since they limit to only well-known, safe domains. When using `InDomain`, the lack of DNS-based protections is part of the reason you must be sure that the `trustedDomains` argument truly only includes trusted domains.

### Does the AntiSSRF support proxies?

**Proxies are not supported by AntiSSRF.** If you configure a proxy on your underlying system, for a particular request, or with environment variables, errors or warnings may or may not be raised. However, if your request successfully uses a proxy, the behavior will likely not match your expectations:

* Only the proxy address itself would be validated against the policy's security requirements.
* AntiSSRF has no control over proxy behavior and cannot be used to block the final destination address.
* Unless the proxy itself is independently configured to use AntiSSRF (or another SSRF protection), SSRF vulnerabilities can occur through the proxy.

For these reasons, do not use proxies with AntiSSRF-protected clients.

### Can I modify a policy after creating a handler, agent, or session?

No. Do not call any policy modification methods (such as `AddAllowedAddresses`, `AddDeniedAddresses`, `AddRequiredHeaders`, etc.) on an `AntiSSRFPolicy` instance after it has been used to create a handler, agent, or session. Modifying the policy after creation may result in errors or unexpected security behavior.

Maintain a 1:1 relationship between policies and request objects: create a separate `AntiSSRFPolicy` instance for each handler/agent/session that needs different security settings.

### How do I know if a domain can be trusted?

A domain should only be treated as trusted when it is fully owned and controlled by your organization, and no customer-configurable subdomains exist.

In practice, this means the domain must not be able to redirect to arbitrary locations, and its DNS registration and resolution behavior must not be changeable by untrusted parties.

`InDomain` does not provide protections against redirect-based attacks or DNS-based attacks. If those risks exist, use `AntiSSRFPolicy` instead.

For Microsoft teams with questions about what domains to trust, please search for the internal version of the library or reach out to us at [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com) for help!

### What IP addresses or subnets should my service block?

It is important to separate HTTP clients intended for internal vs. external requests.

Ideally, for internal requests or if the range of possible IP addresses is known, use the configuration `PolicyConfigOptions.InternalOnly` and ONLY allow the expected ranges.

For external requests, your service should AT LEAST block the internal and special-use IP addresses, included in the configuration `PolicyConfigOptions.ExternalOnlyLatest`.

### Does the AntiSSRF library protect non-TCP connections or support HTTP/3?

No. `AntiSSRFPolicy` and its handlers, agents, and sessions enforce protections only on TCP connections.

Using AntiSSRF handlers, agents, and sessions for HTTP/3 requests (QUIC over UDP), Unix domain sockets, and other non-TCP connections may bypass AntiSSRF protections.

## Troubleshooting

### My outgoing requests are being dropped at the destination because of an invalid X-Forwarded-For header. What should I do?

By default, the external-only configurations of AntiSSRF automatically add an `X-Forwarded-For: "true"` header to outgoing requests that don't already have this header. This is an important security feature that helps protect against access to sensitive, internal endpoints like IMDS which safely drop all requests with the `X-Forwarded-For` header.

However, some destination services may reject requests with this dummy value. If your destination service is rejecting requests because of the `X-Forwarded-For: "true"` header, you can disable this behavior:

```csharp
var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
policy.AddXFFHeader = false; // Disables automatic X-Forwarded-For header addition
```

**Important:** Only disable this feature if you are absolutely certain that:
* Your destination service drops ALL requests with the `X-Forwarded-For` header. For example, you are intentionally accessing IMDS while blocking all external IP addresses.
* **OR** another component in your service stack reliably adds the `X-Forwarded-For` header to all outgoing requests. That way, the policy does not need to add the invalid dummy value to include the header.

For more information, see the [X-Forwarded-For security notes](dotnet-api/antissrfpolicy/properties/addxffheader#security-notes) and `AddXFFHeader` property.
