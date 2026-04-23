---
layout: default
title: inAzureStorageDomain
parent: UriValidator
grand_parent: Node.js API Reference
nav_order: 2
description: "Check if a URI belongs to Azure Storage domains"
---

# URIValidate.inAzureStorageDomain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to an **Azure Storage Domain**.

{: .note }
> * If you instead expect the domain to be another **specific, trusted domain**, see inDomain.
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see inAzureKeyVaultDomain.
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see AntiSSRFPolicy.

## Definition

Validates if `url` is an Azure Storage endpoint.

```js
inAzureStorageDomain(url: URL | string): boolean
```

### Parameters

`url`: `URL | string`

The URL to be evaluated.

### Returns

* `true` if `url` belongs to any of the listed Azure Storage domains.
* `false` if `url` does not belong to any of the listed Azure Storage domains, the `url` is not a valid URL, or the protocol is not HTTP/S.

## Azure Storage Domain Names

`inAzureStorageDomain` will evaluate whether the given parameter belongs to any combination of the following domains and services:

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
