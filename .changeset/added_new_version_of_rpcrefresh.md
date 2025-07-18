---
default: major
---

# Changed RPCRefresh to allow renters to explicitly set the desired spending for refreshed contracts.

Previously, renters had to add to their remaining allowance when refreshing a contract. Now, 
renters can set the allowance of the new contract explicitly without forcing an increase. This
brings RPCRefresh in line with the behavior of RPCForm and RPCRenew.
