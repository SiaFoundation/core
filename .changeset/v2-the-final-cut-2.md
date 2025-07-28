---
default: major
---

# Allow empty miner payout after FinalCut

A remnant of the old v1 `types.Currency` encoding persists in the `Block.MinerPayouts` field. In v2, only a single miner payout is allowed, so its value is fully determined by the sum of the block reward and miner fees. We can therefore omit the value entirely, eliminating a redundant source of truth. It was decided that *requiring* the value to be omitted was too onerous, as it would compel all miners to update. Making the omission optional allows us to enforce it as a hard requirement at some later time, after all miners have updated.