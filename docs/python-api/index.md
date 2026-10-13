---
layout: default
title: Python API Reference
nav_order: 4
description: "Complete API documentation for the AntiSSRF Python Library"
has_children: true
has_toc: false
---


# API Documentation

## AntiSSRF Python Library

The **AntiSSRF Python Library** is a library that provides robust URL validation and HTTP request protection to prevent SSRF vulnerabilities in code. It is designed as an easy, drop-in library with a minimal impact on the engineering team, implemented both as a requests [Session](https://docs.python-requests.org/en/latest/user/advanced/) and as a static URL validator, depending on use case.

## Usage Instructions

The AntiSSRF Library provides validation for different scenarios based on your trust requirements:

| Use Case | Description | Documentation Link |
| --- | --- | --- |
| **General Case** | The untrusted URL can belong to **any domain** or an **untrusted domain**. | [AntiSSRFPolicy](antissrfpolicy) |
| **Azure Key Vault Domain** | The untrusted URL must be an **Azure Key Vault endpoint**. | [URIValidator.in_azure_keyvault_domain](urivalidator/inazurekeyvaultdomain) |
| **Azure Storage Domain** | The untrusted URL must be an **Azure Storage endpoint**. | [URIValidator.in_azure_storage_domain](urivalidator/inazurestoragedomain) |
| **Allowlist of Trusted Domains** | The untrusted URL must belong to a **specific, trusted domain**. | [URIValidator.in_domain](urivalidator/indomain) |

## Classes

| Class | Description |
| --- | --- |
| [AntiSSRFPolicy](antissrfpolicy) | Represents a customizable security policy and provides a requests `Session` to ensure all outgoing requests match the security policy. |
| [IPAddressRanges](../ipaddressranges) | References to common internal and special-purpose address ranges. |
| [URIValidator](urivalidator) | Provides static methods for validating the hostname and protocol of URLs. |
