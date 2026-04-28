---
layout: default
title: InAzureKeyVaultDomain
parent: URIValidator
grand_parent: C# API Reference
nav_order: 3
description: "Check if a URI belongs to Azure Key Vault domains"
---

# URIValidator.InAzureKeyVaultDomain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to an **Azure Key Vault Domain**.

{: .note }
> * If you instead expect the domain to be another **specific, trusted domain**, see [InDomain](indomain.html).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [InAzureStorageDomain](inazurestoragedomain.html).
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy/).

## Definition

Validates if the given input is an Azure Key Vault endpoint. Only supports HTTP and HTTPS protocols.

## Overloads

| Method | Description |
| --- | --- |
| `InAzureKeyVaultDomain(Uri uri)` | Validates if `uri` is an Azure Key Vault endpoint. |
| `InAzureKeyVaultDomain(string address)` | Validates if `address` is an Azure Key Vault endpoint. |

## InAzureKeyVaultDomain(Uri)

```csharp
public static bool InAzureKeyVaultDomain(Uri? untrustedUri)
```

### Parameters

`untrustedUri`: `Uri?`

The URI to be evaluated.

### Returns

`bool`

* `true` if `untrustedUri` belongs to any of the listed Azure Key Vault domains.
* `false` if `untrustedUri` does not belong to any of the listed Azure Key Vault domains, the URI is not valid, or the protocol is not HTTP/S.

## InAzureKeyVaultDomain(string)

```csharp
public static bool InAzureKeyVaultDomain(string? untrustedAddress)
```

### Parameters

`untrustedAddress`: `string?`

The URI string to be evaluated.

### Returns

`bool`

* `true` if `untrustedAddress` belongs to any of the listed Azure Key Vault domains.
* `false` if `untrustedAddress` does not belong to any of the listed Azure Key Vault domains, the string is not a valid URI, or the protocol is not HTTP/S.

## Azure Key Vault Domain Names

`InAzureKeyVaultDomain` will evaluate whether the given parameter belongs to any of the following domains:

* `vault.azure.net`
* `managedhsm.azure.net`
* `vault.azure.cn`
* `managedhsm.azure.cn`
* `vault.usgovcloudapi.net`
* `managedhsm.usgovcloudapi.net`
