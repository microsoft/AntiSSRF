---
layout: default
title: inAzureKeyVaultDomain
parent: URIValidator
grand_parent: Node.js API Reference
nav_order: 3
description: "Check if a URI belongs to Azure Key Vault domains"
---

# URIValidator.inAzureKeyVaultDomain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to an **Azure Key Vault Domain**.

{: .note }
> * If you instead expect the domain to be another **specific, trusted domain**, see [inDomain](indomain.html).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [inAzureStorageDomain](inazurestoragedomain.html).
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy/).

## Definition

Validates if `url` is an Azure Key Vault endpoint.

```js
inAzureKeyVaultDomain(url: URL | string): boolean
```

### Parameters

`url`: `URL | string`

The URL to be evaluated.

### Returns

* `true` if `url` belongs to any of the listed Azure Key Vault domains.
* `false` if `url` does not belong to any of the listed Azure Key Vault domains, the `url` is not a valid URL, or the protocol is not HTTP/S.

## Azure Key Vault Domain Names

`inAzureKeyVaultDomain` will evaluate whether the given parameter belongs to any of the following domains:

* `vault.azure.net`
* `managedhsm.azure.net`
* `vault.azure.cn`
* `managedhsm.azure.cn`
* `vault.usgovcloudapi.net`
* `managedhsm.usgovcloudapi.net`
