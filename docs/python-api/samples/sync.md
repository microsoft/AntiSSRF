---
layout: default
title: Synchronous
parent: Samples
grand_parent: Python API Reference
description: "Sync usage of AntiSSRF session"
---

# AntiSSRFPolicy in Synchronous Applications

## Introduction

The [requests](https://docs.python-requests.org/en/latest/) library is the most commonly used HTTP client for teams using Python at Microsoft. The AntiSSRF Python Library integrates with `requests` through the `AntiSSRFSession`, which extends [`requests.Session`](https://docs.python-requests.org/en/latest/user/advanced/) and applies the `AntiSSRFPolicy` to every outgoing request. The examples below demonstrate how to use the AntiSSRF library in a synchronous application.

{: .note }
> Only requests made through the `AntiSSRFSession` are protected. Calls made with the module-level helpers (for example, `requests.get(...)`) or with a plain `requests.Session` bypass the policy.

## Example

Call [`get_antissrf_session`](../antissrfpolicy/methods/getantissrfsession) to obtain a session that enforces the policy on all requests.

### Setup

Set up the AntiSSRF policy for your specific use case, then get an `AntiSSRFSession` from the policy.

```python
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# Customize the policy for your scenario
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)
policy.add_denied_headers(["X-Custom-Header"])

# Get a session that applies the policy to every request
session = policy.get_antissrf_session()
```

### Use the Session for GET Requests

Every request to an endpoint with untrusted input should use the `session`.

```python
untrusted_url = "<some_https_url_constructed_with_untrusted_input>"

try:
    response = session.get(untrusted_url)
    response.raise_for_status()
    # Will get here if the URL meets the security policy
    print(response.text)
except AntiSSRFError:
    # Will get here if the URL violates the security policy
    pass
except Exception:
    # Will get here if the request fails for some other reason
    pass
```

### Use the Session for POST Requests with Body

The `AntiSSRFSession` works for all HTTP methods.

```python
untrusted_url = "<some_https_url_constructed_with_untrusted_input>"

try:
    response = session.post(untrusted_url, json={"key": "value"})
    response.raise_for_status()
    # Will get here if the URL meets the security policy
except AntiSSRFError:
    # Will get here if the URL violates the security policy
    pass
except Exception:
    # Will get here if the request fails for some other reason
    pass
```

{: .note }
> If you want different examples or if you find any bug while using `AntiSSRFPolicy` with `requests`, please let us know at [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com).
