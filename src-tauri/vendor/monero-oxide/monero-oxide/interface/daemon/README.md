# Monero Daemon Interface

A trait for a connection to a Monero daemon, allowing flexibility over the
choice of transport. From there, all `monero-interface` traits are satisfied.

If you're looking for a literal crate satisfying this, please refer to
[`monero-simple-request-rpc`](https://docs.rs/monero-simple-request-rpc).

This library is usable under no-std, with `alloc`, when the `std` feature (on by
default) is disabled.

### On Allocations and Bounds

This library will not create any allocations due to a response's claimed
length. In order to create an allocation, a response must actually include the
data it claims to have. This prevents a malicious Monero daemon from responding
with a length of `u64::MAX` and immediately causing an out-of-memory kill.

However, a malicious Monero daemon may still respond with a large content
length and then proceed to respond with such a large response. While this
requires the malicious Monero daemon to actually spend their bandwidth,
assigning them a cost to do this, it can still pose significant risks to
clients.

Accordingly, this library tells the transport a bound on the response size.
These bounds attempt to limit the amount of client bandwidth, and memory, a
malicious Monero daemon may waste. Unfortunately, due to Monero's lack of
bounds on block sizes and miner transactions (due to its adaptive scaling),
these bounds may cause this library to be unable to make certain calls if
some presumably ludicrous bounds are exceeded. While this is unlikely to
happen, if you'd like to ensure correctness in every case, even the ludicrous,
you may disable size limits on responses with
`daemon.response_size_limits(false)`.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
