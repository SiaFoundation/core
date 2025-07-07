---
default: minor
---

# consensus: Reject V1BlockSupplement after require height

#329 by @lukechampine

This is somewhat redundant since the chain.DBStore always returns an empty supplement after the require height, but it doesn't hurt to enforce it in core.