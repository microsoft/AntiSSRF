---
layout: default
title: get_antissrf_session
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "getantissrfsession method documentation"
---

# AntiSSRFPolicy.get_antissrf_session Method

## Definition

This method retrieves an `AntiSSRFSession`, which extends [requests.Session](https://docs.python-requests.org/en/latest/user/advanced/) and applies the existing `AntiSSRFPolicy` instance to all requests before sending them. If a request does not meet the requirements of the policy, attempting to make the request will raise an `AntiSSRFError`.

```python
def get_antissrf_session(options: any) -> AntiSSRFSession
```

### Constraints

There are a couple of methods of the session that are used to apply the policy and therefore should not be overwritten. This includes the `mount` method for mounting an `HTTPAdapter` and the `build_connection_pool_key_attributes` method within our custom `AntiSSRFHTTPAdapter` where the SSRF protections are implemented.

### Parameters

`options`: `any`

Any options for a `requests.Session`

## Examples

```python
# Customize the external policy to require the example-required-header header
policy = AntiSSRFPolicy(PolicyConfigOptions.EXTERNAL_ONLY_LATEST)
policy.add_required_headers(["example-required-header"])
session = policy.get_antissrf_session()

# Requests that do not follow the policy will be rejected
try:
    bad_response = session.get(
        "https://learn.microsoft.com/en-us/training/paths/describe-basic-concepts-of-cybersecurity/"
    )
    # Will not get here, since the request does not have the required header
except AntiSSRFError as err:
    # Will get here with the error: AntiSSRFError("Request headers or protocol disallowed by policy")
    pass

# Requests that follow the policy will be made like usual
try:
    good_response = session.get(
        "https://learn.microsoft.com/en-us/training/paths/describe-basic-concepts-of-cybersecurity/",
        headers={"example-required-header": "true"}
    )
    # Will get here, since the request has the required header
except AntiSSRFError as err:
    # Will not get here
    pass
```

## Security Notes

### TOCTOU Vulnerabilities

`AntiSSRFPolicy` only protects requests when it is applied through an `AntiSSRFSession` at the time the request is made.

One common mistake is validating a URL with AntiSSRF before making a request, then using a separate network component to send that request. With this pattern, your request is not protected by AntiSSRF, and you are exposed to TOCTOU-based SSRF vulnerabilities.

### Proxy Support

**Proxies are not supported by AntiSSRF.** If you configure a proxy on your underlying system or for a particular request, no error or warning will be raised. However, the behavior will likely not match your expectations:

- Only the proxy address itself is validated against the policy's security requirements.
- AntiSSRF has no control over proxy behavior and cannot be used to block the final destination address.
- Unless the proxy itself is independently configured to use AntiSSRF (or another SSRF protection), SSRF vulnerabilities can occur through the proxy.

For these reasons, do not use proxies with AntiSSRF-protected clients.

Do not configure proxies via any of the following:

- `session.proxies` dictionary
- Custom `HTTPAdapter` with proxy support
- Any proxy-aware mount configurations
- OS environment variables (`HTTP_PROXY`, `HTTPS_PROXY`)

Note that the `requests` library automatically respects proxy environment variables. Ensure your application does not implicitly use system proxy settings when creating sessions for AntiSSRF.
