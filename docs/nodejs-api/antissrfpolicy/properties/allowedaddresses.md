---
layout: default
title: allowedAddresses
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Node.js API Reference
description: "allowedAddresses property documentation"
---

# AntiSSRFPolicy.allowedAddresses Property

## Definition

The `BlockList` of IP address ranges explicitly allowed by the policy.

```js
ReadOnly<BlockList> allowedAddresses { get; }
```

{: .note }
> `allowedAddresses` takes precedence over `deniedAddresses`, if if an IP address matches both, it will be considered allowed by the policy.

### Property Value

`ReadOnly<BlockList>`

The `ReadOnly` version of the `net.Blocklist` storing the allowed IP addresses.
