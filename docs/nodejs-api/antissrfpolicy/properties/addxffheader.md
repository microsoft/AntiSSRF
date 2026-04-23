---
layout: default
title: addXFFHeader
parent: Properties
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
description: "addXFFHeader property documentation"
---

# AntiSSRFPolicy.addXFFHeader Property

## Definition

Determines whether the `X-Forwarded-For` header should be added to all requests where it is missing.

{: .important }
> The header is added with the dummy value `"true"`. If your end service requires this header to be a valid IP address, you will have to add the header manually.

```js
boolean addXFFHeader { get; set; }
```

### Property Value

`boolean`

* `true` if the `X-Forwarded-For` header should be added to requests where it is missing.
* `false` if the `X-Forwarded-For` header should not be added.

### Errors

`AntiSSRFException`
The value passed cannot be `null` or `undefined`.

### Security Notes

The `X-Forwarded-For` header can be an important defense-in-depth strategy against SSRF vulnerabilities. Some services, including IMDS, will drop all incoming requests with the `X-Forwarded-For` present. By ensuring that the header is added to all outgoing requests, your service can be sure that it will never have an SSRF vulnerability that leaks data from IMDS.
