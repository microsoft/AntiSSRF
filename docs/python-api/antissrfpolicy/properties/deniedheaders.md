---
layout: default
title: denied_headers
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "denied_headers property documentation"
---

# AntiSSRFPolicy.denied_headers Property

## Definition

A read-only list of headers that are forbidden from being included in outgoing requests.

```python
denied_headers: tuple[str]  # read-only
```

{: .note }
> Both `required_headers` and `denied_headers` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`tuple[str]`

A read-only tuple of header names that are blocked by the policy.
