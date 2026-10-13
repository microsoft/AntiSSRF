---
layout: default
title: allowed_addresses
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "allowed_addresses property documentation"
---

# AntiSSRFPolicy.allowed_addresses Property

## Definition

The read-only list of IP networks explicitly allowed by the policy.

```python
allowed_addresses: tuple[IPv6Network]  # read-only
```

{: .note }
> `allowed_addresses` takes precedence over `denied_addresses`. If an IP address matches both, it will be considered allowed by the policy.

### Property Value

`tuple[IPv6Network]`

A read-only tuple copy of the list of allowed IP networks.
