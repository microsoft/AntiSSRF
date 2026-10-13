---
layout: default
title: deny_all_unspecified_ips
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "deny_all_unspecified_ips property documentation"
---

# AntiSSRFPolicy.deny_all_unspecified_ips Property

## Definition

Determines whether all IP addresses should be blocked by default or only `denied_addresses` should be blocked.

{: .note }
> To allow specific addresses, see [add_allowed_addresses](../methods/addallowedaddresses).

```python
deny_all_unspecified_ips: bool  # get / set
```

### Property Value

`bool`

* `True` if all IP addresses NOT specified by `add_allowed_addresses` should be blocked.
* `False` if only addresses in `denied_addresses` should be blocked.

### Errors

`ValueError`
The value set cannot be `None`.

`AntiSSRFError`
When editing after session has been retrieved.

