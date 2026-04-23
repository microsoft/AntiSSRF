---
layout: default
title: denyAllUnspecifiedIPs
parent: Properties
grand_parent: AntiSSRFPolicy
great_grand_parent: Node.js API Reference
description: "denyAllUnspecifiedIPs property documentation"
---

# AntiSSRFPolicy.denyAllUnspecifiedIPs Property

## Definition

Determines whether all IP addresses should be blocked by default or only `deniedAddresses` IP addresses should be blocked.
To allow specific addresses, use `addAllowedAddresses`. 

```js
boolean denyAllUnspecifiedIPs { get; set; }
```

### Property Value

`boolean`

* `true` if all IP addresses NOT specified by `addAllowedAddresses` should be blocked.
* `false` if only addresses in `deniedAddresses` should be blocked.

### Errors

`AntiSSRFException`
The value passed cannot be `null` or `undefined`.
