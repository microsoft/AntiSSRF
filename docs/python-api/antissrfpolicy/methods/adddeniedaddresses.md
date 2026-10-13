---
layout: default
title: add_denied_addresses
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "add_denied_addresses method documentation"
---

# AntiSSRFPolicy.add_denied_addresses Method

## Definition

This method will alter the existing `AntiSSRFPolicy` instance by adding a list of IPv4/IPv6 addresses or subnets that the caller will not be allowed to access.

The external-only configurations add all [internal and special-purpose addresses](../../../ipaddressranges#recommended-ranges-v1) to the policy. The internal-only configuration sets `deny_all_unspecified_ips` to `True`. The blank configuration does not add any denied addresses.

{% include python-api/allowed-denied-precedence-note.md %}

{: .note }
> `deny_all_unspecified_ips` takes precedence over `denied_addresses`. If `deny_all_unspecified_ips` is `True`, `denied_addresses` will not be considered when determining if an IP address is allowed or blocked by the policy.

```python
def add_denied_addresses(networks: list[str]) -> None
```

### Parameters

`networks`: `list[str]`

The list of IPv4 or IPv6 IP addresses or subnets in CIDR notation that the caller will be allowed to access.

{% include python-api/network-formats.md %}

### Errors

`ValueError`

* The `networks` argument is `None` or empty.

`AntiSSRFError`

* Some `network` in `networks` is improperly formatted.
* OR `deny_all_unspecified_ips` is `True`.
* OR editing after a session has been retrieved.

### Examples

If one would like to deny addresses in the network `10.0.0.0/24` in addition to [all internal and special-use IP addresses](../../../ipaddressranges#recommended-ranges-v1), they could do the following:

```python
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# With external configurations, all sensitive IP addresses are blocked by the AntiSSRFPolicy.
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)

# Add additional denied addresses to deny 10.0.0.0/24.
policy.add_denied_addresses(["10.0.0.0/24"])

# Create a session that applies the policy to every request
session = policy.get_antissrf_session()

# These requests are allowed: external addresses outside the denied ranges.
for allowed_url in ["https://bing.com", "https://12.34.56.78", "https://17.2.85.6"]:
    response = session.get(allowed_url)

# These requests are blocked: the newly denied 10.0.0.0/24 plus internal and special-use ranges.
for blocked_url in ["https://10.255.0.0", "https://127.0.0.3", "https://127.25.0.13", "https://192.32.6.17"]:
    try:
        response = session.get(blocked_url)
        # Not reached - the address is blocked by the policy
    except AntiSSRFError:
        # Reached - the address is blocked by the policy
        pass
```