---
layout: default
title: Asynchronous
parent: Samples
grand_parent: Python API Reference
description: "Async usage of AntiSSRF session"
---

# AntiSSRFPolicy in Asynchronous Applications

## Introduction

The `AntiSSRFPolicy` applies its protections through an `AntiSSRFSession`, which extends the synchronous [`requests.Session`](https://docs.python-requests.org/en/latest/user/advanced/). To use the policy from `asyncio` code without blocking the event loop, run the blocking `requests` calls in a worker thread with [`asyncio.to_thread`](https://docs.python.org/3/library/asyncio-task.html#asyncio.to_thread). The examples below demonstrate how to use the AntiSSRF library in an asynchronous application.

{: .warning }
> Do not call `session.get(...)` or `session.post(...)` directly from a coroutine. These calls are blocking and will stall the event loop until the request completes. Always offload them with `asyncio.to_thread`.

## Example

Like `requests.Session`, an `AntiSSRFSession` is not guaranteed to be thread-safe, so prefer creating a fresh session per request (or one per thread) rather than sharing a single session across the worker threads that `asyncio.to_thread` uses.

### Setup

Set up the AntiSSRF policy for your specific use case. A fresh `AntiSSRFSession` is created from this policy for each request in the examples below.

```python
import asyncio
from AntiSSRF import AntiSSRFPolicy, AntiSSRFError, PolicyConfigOptions

# Customize the policy for your scenario
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)
policy.add_denied_headers(["X-Custom-Header"])
```

### Use a Session for GET Requests

Every request to an endpoint with untrusted input should create its own `AntiSSRFSession` from the shared `policy`, offloaded to a worker thread. Use the session as a context manager so it is closed once the request completes.

```python
def get(
    untrusted_url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
):
    # A new session is created per request, but the same policy is reused
    with policy.get_antissrf_session() as session:
        response = session.get(untrusted_url, headers=headers, params=params)
        response.raise_for_status()
        return response


async def request_get(
    untrusted_url: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
):
    try:
        response = await asyncio.to_thread(get, untrusted_url, headers, params)
        # Will get here if the URL meets the security policy
        return response
    except AntiSSRFError:
        # Will get here if the URL violates the security policy
        return None
    except Exception:
        # Will get here if the request fails for some other reason
        return None
```

### Use a Session for POST Requests with Body

The `AntiSSRFSession` works for all HTTP methods. Create the session the same way for a POST request with a body.

```python
def post(untrusted_url: str):
    # A new session is created per request, but the same policy is reused
    with policy.get_antissrf_session() as session:
        response = session.post(untrusted_url, json={"key": "value"})
        response.raise_for_status()
        return response


async def request_post(untrusted_url: str):
    try:
        response = await asyncio.to_thread(post, untrusted_url)
        # Will get here if the URL meets the security policy
        return response
    except AntiSSRFError:
        # Will get here if the URL violates the security policy
        return None
    except Exception:
        # Will get here if the request fails for some other reason
        return None
```

{: .note }
> If you want different examples or if you find any bug while using `AntiSSRFPolicy` in an asynchronous application, please let us know at [antissrf-oss@microsoft.com](mailto:antissrf-oss@microsoft.com).
