---
default: major
---

# Add (State).PowTarget and deprecate v1 fields

The `consensus.State` type contains several redundant and unused PoW-related fields. However, since these fields were included in the Commitment hash, nodes still had to update them correctly. These fields are now zeroed after the hardfork height, so that the Commitment hash can hard-code them if desired.