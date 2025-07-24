---
default: minor
---

# Added RPCRefreshPartial ID and RefreshContractPartialRollover helper

Previously, renters and hosts had to rollover all funds when refreshing a contract. With this change, renters can set their spendable allowance without forcing an increase and hosts only have to rollover their existing risked collateral and revenue. This change increases efficiency of refreshing without compromising the collateral guarantees of existing data or forcing hosts to lock additional collateral that won't be utilized.
