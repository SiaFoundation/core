---
default: minor
---

# Add helpers to get revision as an element from v1/v2 file contract element diffs

#274 by @chris124567

In the old ForEachFileContractElement interface, the revision was provided as a pointer to a (V2)FileContractElement.  In the new system of diffs, the revision is only provided as a (V2)FileContract. There are multiple [places](https://github.com/SiaFoundation/explored/pull/169#discussion_r1950507575) where it is useful to have the revision as an element, and in all of these places more or less the same code will be duplicated unless we create this helper.