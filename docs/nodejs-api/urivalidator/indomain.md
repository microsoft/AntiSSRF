---
layout: default
title: inDomain
parent: URIValidator
grand_parent: Node.js API Reference
nav_order: 1
description: "Check if a URI belongs to specified domain(s)"
---

---
uid: indomain
---

# URIValidator.inDomain Method

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to a **specific set of trusted domains**.

{: .note }
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [inAzureStorageDomain](inazurestoragedomain.html).
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [inAzureKeyVaultDomain](inazurekeyvaultdomain.html).
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see [AntiSSRFPolicy](../antissrfpolicy/).

{: .important }
> If your untrusted URL needs to belong to a specific domain, but you do not fully control all subdomains of the domain, you can use BOTH `inDomain` AND `AntiSSRFPolicy` to be protected.

## Definition

Validates if the given input belongs to any of the specified domains.

## Overloads

| Method | Description |
| --------------- | --------------- |
| `inDomain(url: URL | string, domain: string): boolean` | Validates if `url` belongs to `domain`. |
| `inDomain(url: URL | string, domains: string[]): boolean` | Validates if `url` belongs to any domain in `domains`. |

## inDomain(url: URL | string, domain): boolean

```js
inDomain(url: URL | string, domain: string): boolean
```

### Parameters

`url`: `URL | string`

The URL to be evaluated.

`domain`: `string`

The domain name that `url` will be compared against.

### Returns

* `true` if `url` belongs to `domain`.
* `false` if `url` does not belong `domain`, if `url` cannot be converted to a valid `URL`, if protocol is not HTTP/S or WS/S, or if either argument is invalid.


## inDomain(url: URL | string, domains: string[]): boolean

```js
inDomain(url: URL | string, domains: string[]): boolean
```

### Parameters

`url`: `URL | string`

The URL to be evaluated.

`domains`: `string[]`

The list of domain names that `url` will be compared against.

### Returns

* `true` if `url` belongs to any domain in `domains`.
* `false` if `url` does not belong any domain in `domains`, if `url` cannot be converted to a valid `URL`, if protocol is not HTTP/S or WS/S, or if either argument is invalid.
