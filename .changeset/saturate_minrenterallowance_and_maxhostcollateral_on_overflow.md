---
default: patch
---

# Saturate MinRenterAllowance and MaxHostCollateral on overflow

`MinRenterAllowance` and `MaxHostCollateral` now return `types.MaxCurrency` instead of panicking when the result overflows.
