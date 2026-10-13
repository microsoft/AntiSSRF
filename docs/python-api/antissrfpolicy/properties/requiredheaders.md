---
layout: default
title: required_headers
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "required_headers property documentation"
---

# AntiSSRFPolicy.required_headers Property

## Definition

A read-only list of headers that are required to be present in outgoing requests.

```python
required_headers: tuple[str]  # read-only
```

{: .note }
> Both `required_headers` and `denied_headers` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`tuple[str]`

A read-only tuple of header names that are required by the policy.
