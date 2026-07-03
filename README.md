# [![Sia Core](https://sia.tech/assets/banners/sia-banner-core.png)](http://sia.tech)

[![GoDoc](https://godoc.org/go.sia.tech/core?status.svg)](https://godoc.org/go.sia.tech/core)
[![Go Reference](https://pkg.go.dev/badge/go.sia.tech/core.svg)](https://pkg.go.dev/go.sia.tech/core)

`core` provides the foundational building blocks of the Sia network: the
consensus rules, the peer-to-peer protocol, the renter-host protocol, and the
core types and encoding they all share. It is the reference implementation of
Sia's consensus-critical logic and is depended on by nodes, wallets, hosts, and
tooling across the ecosystem.

It deliberately does *not* include the higher-level components needed to run a
node — a blockchain manager, transaction pool, wallet, or gossip server. Those
build on top of `core` and live in
[coreutils](https://github.com/SiaFoundation/coreutils).

## Packages

- **[types](https://pkg.go.dev/go.sia.tech/core/types)** — the essential types
  of the Sia blockchain (currencies, addresses, transactions, blocks, file
  contracts) and their binary/JSON encoding.
- **[consensus](https://pkg.go.dev/go.sia.tech/core/consensus)** — the Sia
  consensus algorithms: validating and applying blocks, tracking chain state,
  and maintaining the accumulator of unspent elements.
- **[gateway](https://pkg.go.dev/go.sia.tech/core/gateway)** — the peer-to-peer
  protocol used by nodes to discover peers and exchange blocks and transactions.
- **[rhp/v2](https://pkg.go.dev/go.sia.tech/core/rhp/v2),
  [rhp/v3](https://pkg.go.dev/go.sia.tech/core/rhp/v3),
  [rhp/v4](https://pkg.go.dev/go.sia.tech/core/rhp/v4)** — successive versions of
  the renter-host protocol for negotiating and settling storage contracts.
- **[blake2b](https://pkg.go.dev/go.sia.tech/core/blake2b)** — a BLAKE2b
  implementation optimized for the Merkle-tree hashing used throughout Sia.

## Installation

```
go get go.sia.tech/core@latest
```

`core` requires Go 1.26 or later.

## License

`core` is licensed under the [MIT License](LICENSE).
