---
layout: default
title: AllowPlainTextHttp
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: C# API Reference
description: "AllowPlainTextHttp property documentation"
---

# AntiSSRFPolicy.AllowPlainTextHttp Property

{: .warning }
> Setting `AllowPlainTextHttp` to `true` means you will be able to send HTTP requests without the required TLS encryption.

## Definition

Gets or sets whether plain text HTTP requests are allowed. If `false`, any request with the `http` scheme will be blocked by the handler.

```csharp
public bool AllowPlainTextHttp { get; set; }
```

{: .note }
> With ALL configuration options, HTTP is disallowed unless `AllowPlainTextHttp` is explicitly set to `true`.

### Property Value

`bool`

* `true` if HTTP should be allowed.
* `false` if HTTPS should be required.

Default: `false`

### Exceptions

`AntiSSRFException`
Thrown when attempting to change the property after the policy has been used to create a handler via `GetHandler()`.
