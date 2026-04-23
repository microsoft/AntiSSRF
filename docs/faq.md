---
layout: default
title: FAQ
nav_order: 4
description: "Frequently asked questions about AntiSSRF"
---

# Frequently Asked Questions

## General Questions

### What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make requests from the server to internal or external resources. This can lead to:

- Access to internal services and metadata
- Data exfiltration
- Port scanning and reconnaissance
- Potential remote code execution

### How does AntiSSRF protect against SSRF?

AntiSSRF acts as a protective layer for outbound HTTP requests by:

- Blocking requests to dangerous IP ranges (internal networks, localhost, etc.)
- Validating domains against allowlists
- Filtering malicious headers
- Providing configurable security policies

### Which IP ranges are blocked by default?

The recommended policies block:

- **Loopback**: 127.0.0.0/8, ::1/128
- **Private networks**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Link-local**: 169.254.0.0/16, fe80::/10
- **Metadata services**: 169.254.169.254/32 (AWS/Azure IMDS)
- **Other dangerous ranges**: Multicast, broadcast, reserved ranges

## .NET Questions

### What .NET versions are supported?

AntiSSRF supports:
- .NET Standard 2.0+ (compatible with .NET Framework 4.6.1+)
- .NET 8.0+ (latest features and performance)

### Can I use this with HttpClientFactory?

Yes! AntiSSRF works seamlessly with HttpClientFactory:

```csharp
services.AddHttpClient("protected", client => {
    // Configure client
}).ConfigurePrimaryHttpMessageHandler(() => {
    var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
    return policy.GetHandler();
});
```

### Does this affect performance?

The performance impact is minimal:
- IP validation uses efficient CIDR matching
- Domain validation is cached
- No network calls are made during validation

## Node.js Questions

### What Node.js versions are supported?

AntiSSRF requires Node.js 20 or later.

### Can I use this with different HTTP libraries?

AntiSSRF is designed to work with the standard `fetch` API and can be adapted for other HTTP libraries.

### Is TypeScript supported?

Yes, AntiSSRF includes full TypeScript definitions and is written in TypeScript.

## Configuration Questions

### How do I allow requests to specific internal services?

Use the `InternalOnly` policy and explicitly allow your internal ranges:

```csharp
var policy = new AntiSSRFPolicy(PolicyConfigOptions.InternalOnly);
policy.AddAllowedAddresses(["10.0.1.0/24"]); // Your internal API network
```

### Can I validate Azure service domains?

Yes, AntiSSRF includes built-in validation for Azure services:

```csharp
// Check if URL is Azure Storage
bool isAzureStorage = UriValidator.InAzureStorageDomain("https://mystorageaccount.blob.core.windows.net");

// Check if URL is Azure Key Vault  
bool isKeyVault = UriValidator.InAzureKeyVaultDomain("https://myvault.vault.azure.net");
```

### How do I handle false positives?

If legitimate requests are being blocked:

1. Check the blocked IP/domain in logs
2. Add specific exceptions using `AddAllowedAddresses()` or `AddAllowedDomains()`
3. Consider using a less restrictive policy

## Troubleshooting

### My requests are being blocked unexpectedly

1. **Check the IP address**: Use tools like `nslookup` or `dig` to verify the resolved IP
2. **Review your policy**: Ensure you're using the right `PolicyConfigOptions`
3. **Add exceptions**: Use `AddAllowedAddresses()` for specific cases
4. **Enable logging**: Check for `AntiSSRFException` details

### How do I debug policy decisions?

Enable detailed logging in your application to see why requests are blocked:

```csharp
try 
{
    var response = await client.GetAsync(url);
}
catch (AntiSSRFException ex)
{
    _logger.LogWarning("Request blocked: {Message} for URL: {Url}", ex.Message, url);
}
```

### Can I test my configuration?

Yes, create unit tests to verify your policy behavior:

```csharp
[Test]
public void Policy_Should_Block_Internal_IPs()
{
    var policy = new AntiSSRFPolicy(PolicyConfigOptions.ExternalOnlyV1);
    
    Assert.Throws<AntiSSRFException>(() => 
        policy.GetHandler().SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1")));
}
```

## Still Have Questions?

If you can't find the answer here:

1. Check the [Getting Started](getting-started.html) guide
2. Review the [Changelog](changelog.html) for recent changes
3. Open an issue on [GitHub](https://github.com/Microsoft/AntiSSRF)