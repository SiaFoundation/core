---
default: major
---

# Add RHP4 pool RPCs and types for shared balance pools.

Pools let a renter deposit once into a shared backing pool and have multiple accounts draw from it on demand, reducing the per-account allowance needed and the total capital tied up in idle balances. This is especially useful for multi-tenant setups where one party holds the funds and many account keypairs spend from them.