---
layout: default
title: deniedHeaders
parent: Properties
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
description: "deniedHeaders property documentation"
---

# AntiSSRFPolicy.deniedHeaders Property

## Definition

The readonly copy of the list of headers explicitly blocked by the policy. Outgoing requests that include a denied header will be blocked.

```js
readonly string[] deniedHeaders { get; }
```

{: .note }
> Both `requiredHeaders` and `deniedHeaders` are considered when validating a request. If any header is in both lists, the request will always be blocked.

### Property Value

`readonly string[]`

The readonly copy of the list of headers explicitly blocked by the policy.
