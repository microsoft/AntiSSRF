---
layout: default
title: add_allowed_addresses
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "add_allowed_addresses method documentation"
---

# AntiSSRFPolicy.add_allowed_addresses Method

## Definition

This method will alter the existing `AntiSSRFPolicy` instance by adding a list of IPv4/IPv6 addresses or subnets that the caller will be allowed to access.

```python
def add_allowed_addresses(networks: list[str]) -> None
```

{% include python-api/allowed-denied-precedence-note.md %}

### Parameters

`networks`: `list[str]`

The list of IPv4 or IPv6 IP addresses or subnets in CIDR notation that the caller will be allowed to access.

{% include python-api/network-formats.md %}


### Errors

`ValueError`

* The `networks` argument is `None` or empty.

`AntiSSRFError`

* Some `network` in `networks` is improperly formatted.
* Or editing after a session has been retrieved.

## Examples

The specified allowed addresses will act as an exception for denied addresses. For example, if one would like to deny all sensitive IP addresses except for `127.0.0.1` and `192.0.0.0/24`, they could do the following:

```python
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# With external configuration, all sensitive IP addresses are blocked by the AntiSSRFPolicy.
policy = AntiSSRFPolicy(PolicyConfigOptions.NONE)

policy.deny_all_unspecified_ips = True

# Override the denied addresses to specifically allow 127.0.0.1 and 192.0.0.0/24.
policy.add_allowed_addresses(["127.0.0.1", "192.0.0.0/24"])

# Create a session that applies the policy to every request
session = policy.get_antissrf_session()

# These requests are allowed: an external address, plus the explicitly allowed 127.0.0.1 and 192.0.0.0/24.
for allowed_url in ["https://bing.com", "https://127.0.0.1", "https://192.0.0.5", "https://17.2.85.6"]:
    response = session.get(allowed_url)

# These requests are blocked: sensitive addresses outside the explicitly allowed ranges.
for blocked_url in ["https://127.0.0.3", "https://127.25.0.13", "https://192.32.6.17"]:
    try:
        response = session.get(blocked_url)
        # Not reached - the address is blocked by the policy
    except AntiSSRFError:
        # Reached - the address is blocked by the policy
        pass
```
