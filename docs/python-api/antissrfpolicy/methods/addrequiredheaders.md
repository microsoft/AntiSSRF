---
layout: default
title: add_required_headers
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "add_required_headers method documentation"
---

# AntiSSRFPolicy.add_required_headers Method

## Definition

This method will alter the existing `AntiSSRFPolicy` instance to ensure that web requests must contain the specified headers. The library does not add required headers if they are not present in the web requests. For all HTTP requests, header names are case insensitive.

```python
def add_required_headers(required_headers: list[str]) -> None
```

{: .note }
> Both `required_headers` and `denied_headers` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`required_headers`: `list[str]`

The list of headers that must be present in all outgoing requests. If the specified headers are not present in the outgoing requests, the request will not be made.

### Errors

`ValueError`

* The `required_headers` argument is `None` or empty.
* OR some `header` in `required_headers` is `None` or empty.

`AntiSSRFError`

* OR editing after a header has been retrieved.

## Examples

```python
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# Customize the policy
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)
policy.add_required_headers(["Authorization", "X-API-Key"])

# Create a session that applies the policy to every request
session = policy.get_antissrf_session()

# This request succeeds - all required headers are present.
try:
    response = session.get(
        "https://<some_untrusted_hostname>/secure/data",
        headers={
            "Authorization": "Bearer token123",
            "X-API-Key": "key456",
            "Accept": "application/json",
        },
    )
    print("Request successful - all required headers present")
except AntiSSRFError:
    # Not reached
    pass

# This request is blocked - it is missing the required X-API-Key header.
try:
    response = session.get(
        "https://<some_untrusted_hostname>/secure/admin",
        headers={
            "Authorization": "Bearer token123",
            "Accept": "application/json",
        },
    )
    # Not reached
except AntiSSRFError as err:
    print(f"Request blocked due to missing required header: {err}")
```
