---
layout: default
title: AntiSSRFPolicy
parent: C# API Reference
description: "Main policy configuration class for SSRF protection"
has_children: true
---

# AntiSSRFPolicy Class

## Use Case

You would use this class whenever you are accessing a URL that can belong to **any domain** or **some untrusted domain**.

When you are accessing a URL that was constructed with external input (user input or input from other services), you need to make sure the final constructed URL cannot be abused to access unexpected internal endpoints. This class allows you to use built-in configurations or customize your own policy, then provides an [`AntiSSRFHandler`](../antissrfhandler.html) (an `HttpMessageHandler`) that will enforce that policy across all `HttpClient` requests and redirects.

{: .note }
> * If you instead expect the domain to be a **specific, trusted domain**, see [URIValidator.InDomain](../urivalidator/indomain.html).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [URIValidator.InAzureStorageDomain](../urivalidator/inazurestoragedomain.html).
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [URIValidator.InAzureKeyVaultDomain](../urivalidator/inazurekeyvaultdomain.html).

## Definition

Namespace: `Microsoft.Security.AntiSSRF`

Represents a customizable security policy and provides an `AntiSSRFHandler` to ensure all outgoing `HttpClient` requests match the security policy.

```csharp
public class AntiSSRFPolicy
```

## Constructors

| Constructor | Description |
| --- | --- |
| `AntiSSRFPolicy(PolicyConfigOptions config)` | Initializes a new instance of the `AntiSSRFPolicy` class with the specified initial configuration. |

## Properties

| Property | Type | Description |
| --- | --- | --- |
| `AllowPlainTextHttp` | `bool` | Determines whether HTTPS is required or HTTP is allowed. |
| `DenyAllUnspecifiedIPs` | `bool` | Determines whether all IP addresses should be blocked by default or only `DeniedAddresses` IP addresses should be blocked. |
| `AddXFFHeader` | `bool` | Determines whether to add the `X-Forwarded-For` header to requests that are missing the header. |
| `AllowedAddresses` | `IReadOnlyList<string>` | Read-only list of IPv4/IPv6 addresses or subnets that are explicitly allowed by the policy. |
| `DeniedAddresses` | `IReadOnlyList<string>` | Read-only list of IPv4/IPv6 addresses or subnets that are explicitly blocked by the policy. |
| `RequiredHeaders` | `IReadOnlyList<string>` | Read-only list of headers that are required to be present in all outgoing requests. |
| `DeniedHeaders` | `IReadOnlyList<string>` | Read-only list of headers that are forbidden from being included in outgoing requests. |

## Policy Customization Methods

| Method | Description |
| --- | --- |
| `AddAllowedAddresses(string[] networks)` | Adds to a list of IPv4/IPv6 addresses or subnets to be explicitly allowed by the policy. |
| `AddDeniedAddresses(string[] networks)` | Adds to a list of IPv4/IPv6 addresses or subnets to be explicitly blocked by the policy. |
| `AddRequiredHeaders(string[] headers)` | Adds to the list of headers explicitly required by the policy. Outgoing requests that are missing a required header will be blocked. |
| `AddDeniedHeaders(string[] headers)` | Adds to the list of headers explicitly blocked by the policy. Outgoing requests that include a denied header will be blocked. |

## Policy Use Method

| Method | Description |
| --- | --- |
| `GetHandler()` | Creates and returns a new `AntiSSRFHandler` instance based on the current policy configuration. |

## Example

```csharp
using Microsoft.Security.AntiSSRF;
using System.Net.Http;

// Create a policy that blocks internal/special-purpose addresses
AntiSSRFPolicy policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);

// Get the handler and create an HttpClient
AntiSSRFHandler handler = policy.GetHandler();
HttpClient client = new HttpClient(handler);

string untrustedUri = "<some_uri_constructed_with_untrusted_input>";

// All requests through this client are now protected
try
{
    HttpResponseMessage response = await client.GetAsync(untrustedUri);
    // The request was successfully made - the request and untrustedUri matched the policy
}
catch (AntiSSRFException)
{
    // The request was not made - the IP address, headers, or protocol did not match the policy
}

```
