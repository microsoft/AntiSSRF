---
layout: default
title: URIValidator
parent: C# API Reference
description: "URL validation class for SSRF protection"
has_children: true
---

# URIValidator Class

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to a specific set of trusted domains, the Azure Storage domains, or the Azure Key Vault domains.

{: .note }
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy/).

## Definition

Namespace: `Microsoft.Security.AntiSSRF`

Provides static methods for validating the hostname and protocol of URLs.

```csharp
public static class URIValidator
```

## Methods

| Method | Description |
| --- | --- |
| `InDomain(Uri uri, string domain)` | Validates if `uri` belongs to `domain`. |
| `InDomain(string address, string domain)` | Validates if `address` belongs to `domain`. |
| `InDomain(Uri uri, string[] domains)` | Validates if `uri` belongs to any domain in `domains`. |
| `InDomain(string address, string[] domains)` | Validates if `address` belongs to any domain in `domains`. |
| `InAzureKeyVaultDomain(Uri uri)` | Validates if `uri` is an Azure Key Vault endpoint. |
| `InAzureKeyVaultDomain(string address)` | Validates if `address` is an Azure Key Vault endpoint. |
| `InAzureStorageDomain(Uri uri)` | Validates if `uri` is an Azure Storage endpoint. |
| `InAzureStorageDomain(string address)` | Validates if `address` is an Azure Storage endpoint. |
