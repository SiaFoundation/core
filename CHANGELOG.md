## 0.14.3 (2025-07-17)

### Features

- Fixed issues comparing RPCErrors.

## 0.14.2 (2025-07-07)

### Features

#### Add RPCSendHeaders

##330 by @lukechampine

Also removes `RPCSendBlocks` and `RPCSendBlk` (made obsolete by `RPCSendV2Blocks` and `RPCSendCheckpoint`), as well as `RPCRelayHeader` and `RPCSendTransactionSet` (as no more v1 blocks or v1 transactions can be mined). I could maybe see an argument for keeping the latter two, if we wanted to run a v1 testnet, but... why would we want to run a v1 testnet?

#### consensus: Reject V1BlockSupplement after require height

##329 by @lukechampine

This is somewhat redundant since the chain.DBStore always returns an empty supplement after the require height, but it doesn't hurt to enforce it in core.

## 0.14.1 (2025-06-26)

### Fixes

- Fixed JSON encoding of v2 file contract resolution diff.
- Return ErrCommitmentMismatch instead of unnamed error

## 0.14.0 (2025-06-16)

### Breaking Changes

- Drop support for v1 peers in p2p code.

## 0.13.2 (2025-06-14)

### Features

- Add (ElementAccumulator).ValidateTransactionElements

## 0.13.1 (2025-05-26)

### Features

- Added State.MerkleLeafHash helper.

## 0.13.0 (2025-05-26)

### Breaking Changes

- Fixed missing leaf prefix in commitment hash.

## 0.12.4 (2025-05-21)

### Features

- Moved blake2b package out of internal.

## 0.12.3 (2025-05-14)

### Fixes

- Added convenience IDs to V2 transaction JSON marshalling.

## 0.12.2 (2025-05-14)

### Features

- Added UTXO IDs to v1 transaction JSON marshalling

## 0.12.1 (2025-05-14)

### Features

- Adds an `address` field to the JSON representation of Siacoin and Siafund inputs.

## 0.12.0 (2025-04-28)

### Breaking Changes

- Changed contract validation helpers to take current contract as parameter instead of individual values to simplify usage
- Removed unused parameters in contract helpers

## 0.11.0 (2025-04-17)

### Breaking Changes

- Removed `duration` parameter from MinRenterAllowance helper

### Fixes

- Add MaxHostCollateral helper
- Consider post-refresh values for the minRenterAllowance check rather than the additional values.

## 0.10.5 (2025-03-28)

### Fixes

- Add Mul helper to Usage type
- Fixed an issue with memory aliasing of merkle proofs

## 0.10.4 (2025-03-10)

### Fixes

- Fixed several implementations of MaxLen where it was returning a too low number, resulting in decoding errors during contract related RPCs.

## 0.10.3 (2025-02-25)

### Fixes

- Improved `SectorRoot` performance by a factor of 10 by distributing work across available CPU cores
- Update mux dependency to 1.4.0

## 0.10.2 (2025-02-20)

### Features

#### Add helpers to get revision as an element from v1/v2 file contract element diffs

##274 by @chris124567

In the old ForEachFileContractElement interface, the revision was provided as a pointer to a (V2)FileContractElement.  In the new system of diffs, the revision is only provided as a (V2)FileContract. There are multiple [places](https://github.com/SiaFoundation/explored/pull/169#discussion_r1950507575) where it is useful to have the revision as an element, and in all of these places more or less the same code will be duplicated unless we create this helper.

#### Add RPCReplenish to RHP4

Adds an RPC to RHP4 that enables renters to set a target balance instead of first fetching the current balance and then funding the account with the difference. This is primarily to speed up account funding and reduce round trips when managing a large number of accounts.

## 0.10.1 (2025-02-10)

### Fixes

- Fix Siafund ClaimStart not being recorded

## 0.10.0 (2025-02-04)

### Breaking Changes

#### Consensus diffs

##270 by @lukechampine

This replaces the `ForEach` update API with slices of "diffs" -- new types wrapping the various element types. This was originally intended as an ergonomics improvement (since it's annoying to e.g. break out of a `ForEach` callback), but it ended up significantly simplifying most `MidState`-related code: it consolidated the interrelated maps within `MidState`, and enabled a much saner rewrite of the update JSON types.

I originally left the `ForEach` methods in place (with a `// Deprecated` warning), but later removed them entirely; we're going to update all the callsites in `coreutils` anyway, so there's little reason to keep them around. (`ForEachTreeNode` remains, though, since it's used by `explored`.)

#### Fixed a panic when unmarshalling unknown spend policy types

An error will now be returned when trying to encode a transaction with an unset `SpendPolicy`

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
