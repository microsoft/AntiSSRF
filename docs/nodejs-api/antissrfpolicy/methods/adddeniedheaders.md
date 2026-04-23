---
layout: default
title: addDeniedHeaders
parent: Methods
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
nav_order: 1
description: "addDeniedHeaders method documentation"
---

# AntiSSRFPolicy.addDeniedHeaders Method

## Definition

Adds to the list of headers explicitly blocked by the policy. Outgoing requests that include a denied header will be blocked.

```js
addDeniedHeaders(networks: string[]): void
```

{: .note }
> Both `requiredHeaders` and `deniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`headers`: `string[]`

* The list of headers for the policy to block.

### Errors

`AntiSSRFError`
* The `headers` argument is `null` or `undefined`.
* Some `header` in `headers` is `null`, `undefined`, or whitespace.
