## 0.9.1 (2025-01-18)

### Fixes

- Fix account JSON encoding

## 0.9.0 (2024-12-18)

### Breaking Changes

- Add host public key to AccountToken

### Features

- Add helper for generating account tokens

### Fixes

- Allow v1 contracts to be resolved immediately

## 0.8.0 (2024-12-13)

### Breaking Changes

#### Add revisable to RPCLatestRevision

Adds two additional flags to the RPCLatestRevision response. The `Revisable` field indicates whether the host will accept further revisions to the contract. A host will not accept revisions too close to the proof window or revisions on contracts that have already been resolved. The `Renewed` field indicates whether the contract was renewed. If the contract was renewed, the renter can use `FileContractID.V2RenewalID` to get the ID of the new contract.

## 0.7.3 (2024-12-12)

### Features

- Update `golang.org/x/crypto` from 0.30.0 to 0.31.0

## 0.7.2 (2024-12-12)

### Features

#### Allow revisions to set MaxRevisionNumber

`MaxRevisionNumber` was previously used to finalize contracts, but that is not the case anymore, so the restriction can be removed.

### Fixes

- Include storage cost in renter renewal cost

## 0.7.1 (2024-12-04)

### Fixes

- Automate releases
