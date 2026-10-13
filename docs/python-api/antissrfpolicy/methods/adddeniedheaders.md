---
layout: default
title: add_denied_headers
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "add_denied_headers method documentation"
---

# AntiSSRFPolicy.add_denied_headers Method

## Definition

This method will alter the existing `AntiSSRFPolicy` instance to ensure that web requests cannot contain the specified headers. The library does not remove denied headers if they are present in the web requests. For all HTTP requests, header names are case insensitive.

```python
def add_denied_headers(denied_headers: list[str]) -> None
```

{: .note }
> Both `required_headers` and `denied_headers` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`denied_headers`: `list[str]`

The list of headers that cannot be present in any outgoing requests. If any specified headers are present in the outgoing requests, the request will not be made.

### Errors

`ValueError`

* The `denied_headers` argument is `None` or empty.
* OR some `header` in `denied_headers` is `None` or empty.

`AntiSSRFError`

* OR editing after a session has been retrieved.

## Examples

```python
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# Customize the policy
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)
policy.add_denied_headers(["X-Real-IP", "X-Forwarded-Host"])

# Create a session that applies the policy to every request
session = policy.get_antissrf_session()

# This request succeeds - no denied headers are present.
try:
    response = session.get(
        "https://<some_untrusted_hostname>/public/data",
        headers={"User-Agent": "MyApp/1.0", "Accept": "application/json"},
    )
    print("Request successful - no denied headers present")
except AntiSSRFError:
    # Not reached
    pass

# This request is blocked - it contains a denied header.
try:
    response = session.get(
        "https://<some_untrusted_hostname>/admin/endpoint",
        headers={"X-Real-IP": "192.168.1.1", "Accept": "application/json"},  # X-Real-IP is denied
    )
    # Not reached
except AntiSSRFError as err:
    print(f"Request blocked due to denied header: {err}")
```
