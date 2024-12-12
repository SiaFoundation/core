---
default: major
---

# Add revisable to RPCLatestRevision

Adds two additional flags to the RPCLatestRevision response. The `Revisable` field indicates whether the host will accept further revisions to the contract. A host will not accept revisions too close to the proof window or revisions on contracts that have already been resolved. The `Renewed` field indicates whether the contract was renewed. If the contract was renewed, the renter can use `FileContractID.V2RenewalID` to get the ID of the new contract.
