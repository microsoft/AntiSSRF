---
layout: default
title: AntiSSRFHandler
parent: C# API Reference
description: "HttpMessageHandler that enforces AntiSSRF policies"
---

# AntiSSRFHandler Class

## Definition

Namespace: `Microsoft.Security.AntiSSRF`

An `HttpMessageHandler` that enforces the `AntiSSRFPolicy` on all outgoing HTTP requests made via `HttpClient`. This handler performs DNS resolution validation, scheme enforcement, header checks, and redirect following according to the configured policy.

```csharp
public sealed class AntiSSRFHandler : HttpMessageHandler
```

## Remarks

`AntiSSRFHandler` instances are created via `AntiSSRFPolicy.GetHandler()` and should not be constructed directly. The handler is designed to be used with `HttpClient`:

```csharp
var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);
using var handler = policy.GetHandler();
using var client = new HttpClient(handler);
```

The handler enforces the policy at two levels:
1. **HTTP request validation** — Checks the request scheme, denied/required headers, and optionally adds the `X-Forwarded-For` header.
2. **Network connection validation** — On .NET 5+, uses a custom `ConnectCallback` to resolve DNS and verify IP addresses against the policy before establishing a TCP connection. On .NET Standard, validates IP addresses in the `SendAsync` override.

The handler also manages redirects internally, re-validating the policy on each redirect hop.

## Properties

| Property | Type | Description |
| --- | --- | --- |
| `AllowAutoRedirect` | `bool` | Gets or sets whether the handler should automatically follow HTTP redirects. Default: `true`. |
| `MaxAutomaticRedirections` | `int` | Gets or sets the maximum number of redirects to follow. Default: `50`. |
| `Credentials` | `ICredentials?` | Gets or sets the credentials to use for outgoing requests. |
| `MaxConnectionsPerServer` | `int` | Gets or sets the maximum number of concurrent connections per server. |
| `MaxResponseHeadersLength` | `int` | Gets or sets the maximum length of response headers in kilobytes. |

### .NET 5+ Only Properties

| Property | Type | Description |
| --- | --- | --- |
| `CookieContainer` | `CookieContainer` | Gets or sets the cookie container for outgoing requests. |
| `UseCookies` | `bool` | Gets or sets whether cookies should be sent with requests. |
| `ConnectTimeout` | `TimeSpan` | Gets or sets the timeout for establishing a connection. |
| `ResponseDrainTimeout` | `TimeSpan` | Gets or sets the timeout for draining the response content. |
| `PooledConnectionIdleTimeout` | `TimeSpan` | Gets or sets the idle timeout for pooled connections. |
| `PooledConnectionLifetime` | `TimeSpan` | Gets or sets the maximum lifetime for pooled connections. |
| `SslOptions` | `SslClientAuthenticationOptions` | Gets or sets the SSL/TLS options for outgoing requests. |

### .NET Standard Only Properties

| Property | Type | Description |
| --- | --- | --- |
| `CheckCertificateRevocationList` | `bool` | Gets or sets whether the certificate revocation list is checked during SSL/TLS handshake. |
| `ServerCertificateCustomValidationCallback` | `Func<...>?` | Gets or sets a custom callback for server certificate validation. |
| `SslProtocols` | `SslProtocols` | Gets or sets the SSL/TLS protocols to use. |

## Exceptions

All properties throw `ObjectDisposedException` if the handler has been disposed, and `InvalidOperationException` if modified after a request has been sent.

`MaxAutomaticRedirections` throws `ArgumentOutOfRangeException` if set to a value less than or equal to 0.

## Example

```csharp
using Microsoft.Security.AntiSSRF;
using System.Net.Http;

var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyLatest);

using var handler = policy.GetHandler();
handler.AllowAutoRedirect = true;
handler.MaxAutomaticRedirections = 10;

string untrustedUri = "<some_uri_constructed_with_untrusted_input>";

using var client = new HttpClient(handler);
var response = await client.GetAsync(untrustedUri);
```
