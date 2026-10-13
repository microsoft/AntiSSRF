---
layout: default
title: add_xff_header
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "add_xff_header property documentation"
---

# AntiSSRFPolicy.add_xff_header Property

## Definition

Determines whether to automatically add the `X-Forwarded-For` header to outgoing requests that don't already include it.

{: .important }
> The header is added with the dummy value `"true"`. If your end service requires this header to be a valid IP address, you will have to add the header manually.

```python
add_xff_header: bool  # get / set
```

### Property Value

`bool`

* `True` if the `X-Forwarded-For` header should be added to requests that don't already include it.
* `False` if the `X-Forwarded-For` header should not be added.

### Errors

`ValueError`
The value set cannot be `None`.

`AntiSSRFError`
When editing after session has been retrieved.

## Security Notes

The `X-Forwarded-For` header can be an important defense-in-depth strategy against SSRF vulnerabilities. Some services, including IMDS, will drop all incoming requests with the `X-Forwarded-For` header present. By ensuring that the header is added to all outgoing requests, your service can be sure that it will never have an SSRF vulnerability that leaks data from IMDS.
