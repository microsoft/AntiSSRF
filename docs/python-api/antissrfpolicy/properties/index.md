---
layout: default
title: Properties
parent: AntiSSRFPolicy
grand_parent: Python API Reference
nav_order: 2
description: "AntiSSRFPolicy properties documentation"
has_children: true
nav_fold: true
has_toc: false
---

# AntiSSRFPolicy Properties

| Property | Description |
| --- | --- |
| [add_xff_header](addxffheader) | Determines whether to automatically add the `X-Forwarded-For` header to outgoing requests that don't already include it. |
| [allowed_addresses](allowedaddresses) | List of IP networks that are explicitly allowed by the policy. |
| [allow_plain_text_http](allowplaintexthttp) | Determines whether HTTPS is required or HTTP is allowed. |
| [denied_addresses](deniedaddresses) | List of IP networks that are explicitly blocked by the policy. |
| [denied_headers](deniedheaders) | List of headers that are forbidden from being included in outgoing requests. |
| [deny_all_unspecified_ips](denyallunspecifiedips) | Determines whether all IP addresses should be blocked by default or only `denied_addresses` should be blocked. |
| [required_headers](requiredheaders) | List of headers that are required to be present in outgoing requests. |
