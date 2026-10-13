---
layout: default
title: in_azure_keyvault_domain
parent: URIValidator
grand_parent: Python API Reference
description: "Check if a URI belongs to Azure Key Vault domains"
---

# URIValidator.in_azure_keyvault_domain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

**AND**

The URL is expected to belong to an **Azure Key Vault Domain**.

{: .note }
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [in_azure_storage_domain](inazurestoragedomain).
> * If you instead expect the domain to be another **specific, trusted domain**, see [in_domain](indomain).

## Definition

Validates if a URL is an Azure Key Vault endpoint.

```python
def in_azure_keyvault_domain(url: str) -> bool
```

### Parameters

`url`: `str`

The URL to be evaluated.

### Returns

* `True` if `url` belongs to an Azure Key Vault domain.
* `False` if `url` does not belong to an Azure Key Vault domain, the `url` is not a valid URL, or the protocol is not HTTP/S.

## Examples

```python
from AntiSSRF import URIValidator

URIValidator.in_azure_keyvault_domain('https://myvault.vault.azure.net/secrets/api-key')
# → True

URIValidator.in_azure_keyvault_domain('https://evil.com/secrets')
# → False
```

## Azure Key Vault Domain Names

`in_azure_keyvault_domain` will evaluate whether the given parameter belongs to any of the following domains:

* `vault.azure.net`
* `managedhsm.azure.net`
* `vault.azure.cn`
* `managedhsm.azure.cn`
* `vault.usgovcloudapi.net`
* `managedhsm.usgovcloudapi.net`

