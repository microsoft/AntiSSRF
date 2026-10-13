---
layout: default
title: denied_addresses
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "denied_addresses property documentation"
---

# AntiSSRFPolicy.denied_addresses Property

## Definition

The read-only list of IP networks explicitly blocked by the policy.

```python
denied_addresses: tuple[IPv6Network]  # read-only
```

{: .note }
> `allowed_addresses` takes precedence over `denied_addresses`. If an IP address matches both, it will be considered allowed by the policy.

{: .note }
> `deny_all_unspecified_ips` takes precedence over `denied_addresses`. If `deny_all_unspecified_ips` is `True`, `denied_addresses` will not be considered when determining if an IP address is allowed or blocked by the policy.

### Property Value

`tuple[IPv6Network]`

A read-only tuple copy of the list of denied IP networks.
