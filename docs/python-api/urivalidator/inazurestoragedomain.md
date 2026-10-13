---
layout: default
title: in_azure_storage_domain
parent: URIValidator
grand_parent: Python API Reference
description: "Check if a URI belongs to Azure Storage domains"
---

# URIValidator.in_azure_storage_domain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

**AND**

The URL is expected to belong to an **Azure Storage Domain**.

{: .note }
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy).
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [in_azure_keyvault_domain](inazurekeyvaultdomain).
> * If you instead expect the domain to be another **specific, trusted domain**, see [in_domain](indomain).


## Definition

Validates if a URL is an Azure Storage endpoint.

```python
def in_azure_storage_domain(url: str) -> bool
```

### Parameters

`url`: `str`

The URL to be evaluated.

### Returns

* `True` if `url` belongs to an Azure Storage domain.
* `False` if `url` does not belong to an Azure Storage domain, the `url` is not a valid URL, or the protocol is not HTTP/S.

## Examples

```python
from AntiSSRF import URIValidator

URIValidator.in_azure_storage_domain('https://mystorageaccount.blob.core.windows.net/container/file.txt')
# → True

URIValidator.in_azure_storage_domain('https://evil.com/data')
# → False
```

## Azure Storage Domain Names

`in_azure_storage_domain` will evaluate whether the given parameter belongs to any combination of the following domains and services:

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

