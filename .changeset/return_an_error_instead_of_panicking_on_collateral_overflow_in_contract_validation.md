---
default: patch
---

# Return an error instead of panicking on collateral overflow in contract validation.

`RPCRenewContractRequest.Validate` and `RPCRefreshContractRequest.Validate` added the renter-supplied collateral with `Currency.Add`, which panics on overflow, before comparing it to the host's max collateral. They now check the collateral first and use `AddWithOverflow`, so an oversized value returns a bad-request error. `RPCFormContractRequest.Validate` also checks the max collateral before computing the minimum allowance.
