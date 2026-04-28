---
layout: default
title: deniedAddresses
parent: Properties
grand_parent: AntiSSRFPolicy
ancestor: Node.js API Reference
description: "deniedAddresses property documentation"
---

# AntiSSRFPolicy.deniedAddresses Property

## Definition

The `BlockList` of IP address ranges explicitly blocked by the policy.

```js
ReadOnly<BlockList> deniedAddresses { get; }
```

{: .note }
> `allowedAddresses` takes precedence over `deniedAddresses`, if if an IP address matches both, it will be considered allowed by the policy.

{: .note }
> `denyAllUnspecifiedIPs` takes precedence over `deniedAddresses`, if `denyAllUnspecifiedIPs` is `true`, `deniedAddresses` will not be considered when determining if an IP address is allowed or blocked by the policy.

### Property Value

`ReadOnly<BlockList>`

The `ReadOnly` version of the `net.Blocklist` storing the denied IP addresses.
