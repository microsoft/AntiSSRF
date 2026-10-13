---
layout: default
title: Methods
parent: AntiSSRFPolicy
grand_parent: Python API Reference
nav_order: 3
description: "AntiSSRFPolicy methods documentation"
has_children: true
nav_fold: true
has_toc: false
---

## Policy Customization Methods

| Method | Description |
| --- | --- |
| [add_allowed_addresses(list[str])](addallowedaddresses) | Adds IP networks to be explicitly allowed by the policy. |
| [add_denied_addresses(list[str])](adddeniedaddresses) | Adds IP networks to be explicitly blocked by the policy. |
| [add_denied_headers(list[str])](adddeniedheaders) | Adds headers to be explicitly blocked by the policy. |
| [add_required_headers(list[str])](addrequiredheaders) | Adds headers to be explicitly required by the policy. |

## Policy Use Methods

| Method | Description |
| --- | --- |
| [get_antissrf_session(any) -> AntiSSRFSession](getantissrfsession) | Builds a [requests.Session](https://docs.python-requests.org/en/latest/user/advanced/) that enforces `AntiSSRFPolicy` on all outgoing requests. |

