---
default: minor
---

# Add RPCSendHeaders

#330 by @lukechampine

Also removes `RPCSendBlocks` and `RPCSendBlk` (made obsolete by `RPCSendV2Blocks` and `RPCSendCheckpoint`), as well as `RPCRelayHeader` and `RPCSendTransactionSet` (as no more v1 blocks or v1 transactions can be mined). I could maybe see an argument for keeping the latter two, if we wanted to run a v1 testnet, but... why would we want to run a v1 testnet?
