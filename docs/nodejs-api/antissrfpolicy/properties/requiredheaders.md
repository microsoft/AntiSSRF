---
layout: default
title: requiredHeaders
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Node.js API Reference
description: "requiredHeaders property documentation"
---

# AntiSSRFPolicy.requiredHeaders Property

## Definition

The readonly copy of the list of headers explicitly required by the policy. Outgoing requests that are missing a required header will be blocked.

```js
readonly string[] requiredHeaders { get; }
```

{: .note }
> Both `requiredHeaders` and `deniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`readonly string[]`

The readonly copy of the list of headers explicitly required by the policy.
