---
layout: default
title: C# API Reference
nav_order: 4
description: "Complete API documentation for the AntiSSRF C# library"
has_children: true
has_toc: false
---

# API Documentation

## AntiSSRF C# Library

The **AntiSSRF C# Library** is a library for .NET applications that provides robust URL validation and HTTP request protection to prevent SSRF vulnerabilities in code. It is designed as an easy, drop-in library with minimal impact on the engineering team, implemented both as an `HttpMessageHandler` for use with `HttpClient` and as a static URL validator, depending on use case.

## Usage Instructions

There are four different ways to use this library, depending on your specific case. Identify the use case below based on the URLs your code is accessing.

| Use Case | Steps |
| --- | --- |
| The URL you are accessing must always belong to a **specific, trusted domain**. | See [URIValidator.InDomain](urivalidator/indomain.html). |
| The URL you are accessing must be an **Azure Storage endpoint**. | See [URIValidator.InAzureStorageDomain](urivalidator/inazurestoragedomain.html). |
| The URL you are accessing must be an **Azure Key Vault endpoint**. | See [URIValidator.InAzureKeyVaultDomain](urivalidator/inazurekeyvaultdomain.html). |
| The URL you are accessing can belong to **any domain** or an **untrusted domain**, so to prevent SSRF vulnerabilities, you must ensure that it does not resolve to internal and special-purpose IP addresses. | See [AntiSSRFPolicy](antissrfpolicy/). |

## Classes

| Class | Description |
| --- | --- |
| [AntiSSRFPolicy](antissrfpolicy/) | Represents a customizable security policy and provides an `AntiSSRFHandler` to ensure all outgoing `HttpClient` requests match the security policy. |
| [AntiSSRFHandler](antissrfhandler.html) | An `HttpMessageHandler` that enforces the `AntiSSRFPolicy` on all outgoing requests made via `HttpClient`. |
| [IPAddressRanges](ipaddressranges.html) | Provides predefined IP address ranges for use with AntiSSRF policies. |
| [URIValidator](urivalidator/) | Provides static methods for validating the hostname and protocol of URLs. |