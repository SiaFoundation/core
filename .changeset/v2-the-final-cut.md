---
default: major
---

# Add FinalCut difficulty adjustment

The v2 difficulty adjustment algorithm is buggy, leading to higher variance in observed block times. We've fixed the algorithm and confirmed that it exhibits the correct behavior in simulations.

# Add (State).PowTarget and deprecate v1 fields

The `consensus.State` type contains several redundant and unused PoW-related fields. However, since these fields were included in the Commitment hash, nodes still had to update them correctly. These fields are now zeroed after the hardfork height, so that the Commitment hash can hard-code them if desired.

# Allow empty miner payout after FinalCut

A remnant of the old v1 `types.Currency` encoding persists in the `Block.MinerPayouts` field. In v2, only a single miner payout is allowed, so its value is fully determined by the sum of the block reward and miner fees. We can therefore omit the value entirely, eliminating a redundant source of truth. It was decided that *requiring* the value to be omitted was too onerous, as it would compel all miners to update. Making the omission optional allows us to enforce it as a hard requirement at some later time, after all miners have updated.