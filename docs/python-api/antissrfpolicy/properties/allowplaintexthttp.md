---
layout: default
title: allow_plain_text_http
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Python API Reference
description: "allow_plain_text_http property documentation"
---

# AntiSSRFPolicy.allow_plain_text_http Property

{: .warning }
> Changing an `AntiSSRFPolicy` instance to allow plaintext HTTP means you will be able to send HTTP requests without the recommended TLS encryption.

## Definition

Determines whether HTTPS is required or HTTP is allowed.

```python
allow_plain_text_http: bool  # get / set
```

{: .note }
> With ALL configuration options, HTTP is disallowed unless `allow_plain_text_http` is explicitly set to `True`.

### Property Value

`bool`

* `True` if HTTP should be allowed.
* `False` if HTTPS should be required.

### Errors

`ValueError`
The value set cannot be `None`.

`AntiSSRFError`
When editing after session has been retrieved.
