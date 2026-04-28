---
layout: default
title: InAzureStorageDomain
parent: URIValidator
grand_parent: C# API Reference
nav_order: 2
description: "Check if a URI belongs to Azure Storage domains"
---

# URIValidator.InAzureStorageDomain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to an **Azure Storage Domain**.

{: .note }
> * If you instead expect the domain to be another **specific, trusted domain**, see [InDomain](indomain.html).
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [InAzureKeyVaultDomain](inazurekeyvaultdomain.html).
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy/).

## Definition

Validates if the given input is an Azure Storage endpoint. Only supports HTTP and HTTPS protocols.

## Overloads

| Method | Description |
| --- | --- |
| `InAzureStorageDomain(Uri uri)` | Validates if `uri` is an Azure Storage endpoint. |
| `InAzureStorageDomain(string address)` | Validates if `address` is an Azure Storage endpoint. |

## InAzureStorageDomain(Uri)

```csharp
public static bool InAzureStorageDomain(Uri? untrustedUri)
```

### Parameters

`untrustedUri`: `Uri?`

The URI to be evaluated.

### Returns

`bool`

* `true` if `untrustedUri` belongs to any of the listed Azure Storage domains.
* `false` if `untrustedUri` does not belong to any of the listed Azure Storage domains, the URI is not valid, or the protocol is not HTTP/S.

## InAzureStorageDomain(string)

```csharp
public static bool InAzureStorageDomain(string? untrustedAddress)
```

### Parameters

`untrustedAddress`: `string?`

The URI string to be evaluated.

### Returns

`bool`

* `true` if `untrustedAddress` belongs to any of the listed Azure Storage domains.
* `false` if `untrustedAddress` does not belong to any of the listed Azure Storage domains, the string is not a valid URI, or the protocol is not HTTP/S.

## Azure Storage Domain Names

`InAzureStorageDomain` will evaluate whether the given parameter belongs to any combination of the following domains and services:

**Domains:**
- `core.windows.net`
- `storage.azure.net`
- `core.usgovcloudapi.net`
- `core.chinacloudapi.cn`

**Services:**
- `blob`
- `web`
- `dfs`
- `file`
- `queue`
- `table`
