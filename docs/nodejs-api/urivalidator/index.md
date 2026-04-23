---
layout: default
title: URIValidator
parent: Node.js API Reference
description: "URL validation class for SSRF protection"
has_children: true
---

# URIValidator Class

## Use Case

The code is making requests to a URL constructed using untrusted inputs, where an input is considered untrusted if it comes from *user input* or *other services*.

AND

The URL is expected to belong to a specific set of trusted domains, the Azure Storage domains, or the Azure Key Vault domains.

{: .note }
> * If you instead expect the domain to be in **any domain** or **an untrusted domain**, see AntiSSRFPolicy.

## Definition

Provides methods for validating the hostname and protocol of URLs.

## Methods

| Method | Description |
| --- | --- |
| `inDomain(url: URL | string, domain: string)` | Validates if `url` belongs to `domain`. |
| `inDomain(url: URL | string, domains: string[])` | Validates if `url` belongs to any domain in `domains`. |
| `inAzureKeyVaultDomain(url: URL | string)` | Validates if `url` is an Azure Key Vault endpoint. |
| `inAzureStorageDomain(url: URL | string)` | Validates if `url` is an Azure Storage endpoint. |
