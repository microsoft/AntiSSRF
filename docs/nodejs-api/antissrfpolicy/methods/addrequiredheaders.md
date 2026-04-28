---
layout: default
title: addRequiredHeaders
parent: Methods
grand_parent: AntiSSRFPolicy
ancestor: Node.js API Reference
nav_order: 1
description: "addRequiredHeaders method documentation"
---

# AntiSSRFPolicy.addRequiredHeaders Method

## Definition

Adding to the list of headers explicitly required by the policy. Outgoing requests that are missing a required header will be blocked.

```js
addRequiredHeaders(networks: string[]): void
```

{: .note }
> Both `requiredHeaders` and `deniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Parameters

`headers`: `string[]`

* The list of headers for the policy to require.

### Errors

`AntiSSRFError`
* The `headers` argument is `null` or `undefined`.
* Some `header` in `headers` is `null`, `undefined`, or whitespace.
