---
layout: default
title: AntiSSRFPolicy
parent: Python API Reference
description: "Main policy configuration class for SSRF protections"
nav_order: 1
has_children: true
has_toc: false
---

# AntiSSRFPolicy Class

## Use Case

Use this class whenever you are accessing a URL that can belong to **any domain** or **some untrusted domain**.

This use case addresses two distinct security scenarios. For requests to external endpoints, the policy enforces that IP addresses are not internal or special-use addresses, preventing URLs from being abused to gain access to internal resources. For requests to backend resources, the policy blocks all IP addresses except for specific ranges that you expect to see, ensuring that URLs cannot be used to exfiltrate data to unauthorized destinations.

{: .note }
> * If you instead expect the URL to be an **Azure Key Vault endpoint**, see [URIValidator.in_azure_keyvault_domain](../urivalidator/inazurekeyvaultdomain).
> * If you instead expect the URL to be an **Azure Storage endpoint**, see [URIValidator.in_azure_storage_domain](../urivalidator/inazurestoragedomain).
> * If you instead expect the domain to be a **specific, trusted domain**, see [URIValidator.in_domain](../urivalidator/indomain).

## Definition

The `AntiSSRFPolicy` allows you to customize security requirements for headers, IP addresses, and protocols. You can configure the policy using built-in settings or define your own custom rules. The policy then provides a `requests.Session` that automatically enforces these security requirements on all outgoing requests made using the `Session`.

{: .important }
> `AntiSSRFPolicy` only protects requests when it is applied through a `Session` from `get_antissrf_session` at the time the request is made.
>
> Using `AntiSSRFPolicy` only to validate a URL before making the request separately bypasses its TOCTOU protections. If the request is not sent through the `Session` created by `get_antissrf_session`, you will not be protected.

## Constructors

| Constructor | Description |
| --- | --- |
| [AntiSSRFPolicy(PolicyConfigOptions)](constructor) | Initializes a new instance of the `AntiSSRFPolicy` class with the specified initial configuration. |

## Properties

| Property | Description |
| --- | --- |
| [add_xff_header](properties/addxffheader) | Determines whether to automatically add the `X-Forwarded-For` header to outgoing requests that don't already include it. |
| [allowed_addresses](properties/allowedaddresses) | List of IP networks that are explicitly allowed by the policy. |
| [allow_plain_text_http](properties/allowplaintexthttp) | Determines whether HTTPS is required or HTTP is allowed. |
| [denied_addresses](properties/deniedaddresses) | List of IP networks that are explicitly blocked by the policy. |
| [denied_headers](properties/deniedheaders) | List of headers that are forbidden from being included in outgoing requests. |
| [deny_all_unspecified_ips](properties/denyallunspecifiedips) | Determines whether all IP addresses should be blocked by default or only `denied_addresses` should be blocked. |
| [required_headers](properties/requiredheaders) | List of headers that are required to be present in outgoing requests. |

## Policy Customization Methods

| Method | Description |
| --- | --- |
| [add_allowed_addresses(list[str])](methods/addallowedaddresses) | Adds IP networks to be explicitly allowed by the policy. |
| [add_denied_addresses(list[str])](methods/adddeniedaddresses) | Adds IP networks to be explicitly blocked by the policy. |
| [add_denied_headers(list[str])](methods/adddeniedheaders) | Adds headers to be explicitly blocked by the policy. |
| [add_required_headers(list[str])](methods/addrequiredheaders) | Adds headers to be explicitly required by the policy. |

## Policy Use Methods

| Method | Description | 
| --- | --- | 
| [get_antissrf_session(any)](methods/getantissrfsession) | Builds a [requests.Session](https://docs.python-requests.org/en/latest/user/advanced/) that will enforce the policy on all outgoing requests. | 