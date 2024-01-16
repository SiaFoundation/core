# [![Sia Core](https://sia.tech/assets/banners/sia-banner-core.png)](http://sia.tech)

[![GoDoc](https://godoc.org/go.sia.tech/core?status.svg)](https://godoc.org/go.sia.tech/core)

This repo contains the Sia consensus and p2p packages, along with foundational
types and functions. It does *not* contain many key components of a runnable
node, such as a blockchain manager, transaction pool, wallet, or gossip server;
for those, see [coreutils](https://github.com/SiaFoundation/coreutils).
