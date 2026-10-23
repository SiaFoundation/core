---
default: patch
---

Improve performance of element accumulator insertion, batched Merkle proof updates, proof lookup, RHP diff-proof verification, and multiproof decoding.

Fix JSON round-trips of consensus apply and revert updates so deserialized updates preserve their Merkle proof update behavior.
