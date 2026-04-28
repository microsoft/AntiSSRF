---
layout: default
title: Node.js API Reference
nav_order: 3
description: "Complete API documentation for the AntiSSRF Node.js library"
has_children: true
has_toc: false
---

# API Documentation

## AntiSSRF JavaScript Library

The  **AntiSSRF NodeJS Library** is a library for JavaScript/TypeScript applications using Node.js that provides robust URL validation to prevent SSRF vulnerabilities in code. It is designed as an easy, drop-in library with a minimal impact on the engineering team, implemented both as a NodeJS HTTP(S) Agent and URL validator, depending on use case.

## Usage Instructions

There are four different ways to use this library, depending on your specific case. Identify the use case below based on the URLs your code is accessing.

| Use Case | Steps |
| --- | --- |
| The URL you are accessing must always belong to a **specific, trsuted domain**. | See URIValidator.inDomain. |
| The URL you are accessing must be an **Azure Storage endpoint**. | See URIValidator.inAzureStorageDomain. |
| The URL you are accessing must be an **Azure Key Vault endpoint**. | See URIValidator.inAzureKeyVaultDomain. |
| The URL you are accessing can belong to **any domain** or an **untrusted domain**, so to prevent SSRF vulnerabilities, you must ensure that it does not resolve to internal and special-purpose IP addresses. | See AntiSSRFPolicy. |

## Classes

| Class | Description |
| --- | --- |
| [AntiSSRFPolicy](antissrfpolicy/) | Represents a customizable security policy and provides HTTP(S) agents to ensure all outgoing requests match the security policy. |
| [IPAddressRanges](../ipaddressranges.html) | Provides predefined IP address ranges for use with AntiSSRF policies. |
| [URIValidator](urivalidator/) | Provides methods for validating the hostname of URLs. |
