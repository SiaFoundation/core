---
default: minor
---

# Add RPCReplenish to RHP4

Adds an RPC to RHP4 that enables renters to set a target balance instead of first fetching the current balance and then funding the account with the difference. This is primarily to speed up account funding and reduce round trips when managing a large number of accounts.