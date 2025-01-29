---
default: major
---

# Fixed a panic when unmarshalling unknown spend policy types

An error will now be returned when trying to encode a transaction with an unset `SpendPolicy`
