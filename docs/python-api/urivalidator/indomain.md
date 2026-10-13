---
layout: default
title: in_domain
parent: URIValidator
grand_parent: Python API Reference
description: "Check if a URI belongs to specified domain(s)"
---

# URIValidator.in_domain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

**AND**

The URL is expected to belong to a **specific set of trusted domains**.

{: .note }
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy).
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [in_azure_keyvault_domain](inazurekeyvaultdomain).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [in_azure_storage_domain](inazurestoragedomain).

{: .important }
> If your untrusted URL needs to belong to a specific domain, but you do not fully control all subdomains of the domain, you can use BOTH `in_domain` AND `AntiSSRFPolicy` to be protected. If the untrusted URL belongs to a domain that cannot be fully trusted, at least `AntiSSRFPolicy` is required for full protection.

## Definition

Validates if a URL belongs to any of a list of trusted domains.

## Overloads

| Method | Description |
| --------------- | --------------- |
| [in_domain(str, str) -> bool](#indomain-str) | Validates if a URL belongs to a trusted domain. |
| [in_domain(str, list[str]) -> bool](#indomain-str-array) | Validates if a URL belongs to any of a list of trusted domains. |

<h2 id="indomain-str">in_domain(str, str) -> bool</h2>

```python
def in_domain(untrusted_url: str, trusted_domain: str) -> bool
```

### Parameters

`untrusted_url`: `str`

The URL to be evaluated.

`trusted_domain`: `str`

The domain name that `untrusted_url` will be compared against.

### Returns

* `True` if `untrusted_url` belongs to `trusted_domain`.
* `False` if `untrusted_url` does not belong to `trusted_domain`, if `untrusted_url` cannot be parsed as a valid URL, if the protocol is not HTTP/S or WS/S, or if either argument is invalid.


<h2 id="indomain-str-array">in_domain(str, list[str]) -> bool</h2>

```python
def in_domain(untrusted_url: str, trusted_domains: list[str]) -> bool
```

### Parameters

`untrusted_url`: `str`

The URL to be evaluated.

`trusted_domains`: `list[str]`

The list of domain names that `untrusted_url` will be compared against.

### Returns

* `True` if `untrusted_url` belongs to any domain in `trusted_domains`.
* `False` if `untrusted_url` does not belong to any domain in `trusted_domains`, if `untrusted_url` cannot be parsed as a valid URL, if the protocol is not HTTP/S or WS/S, or if either argument is invalid.

## Examples

```python
from AntiSSRF import URIValidator

URIValidator.in_domain('https://api.mycompany.com/data', 'mycompany.com')
# → True

URIValidator.in_domain('https://api.mycompany.com/data', ['mycompany.com', 'trusted.com'])
# → True

URIValidator.in_domain('https://evil.com/secrets', 'mycompany.com')
# → False
```
