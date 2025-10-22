# pfnatd

[Easy NAT] mode (aka [Endpoint-Independent Mapping][rfc4787]) for OpenBSD [pf]. The pfnatd daemon monitors packets via [pflog]. When it sees [STUN] traffic, it adds a NAT rule to ensure that subsequent UDP packets from the same source are mapped to the same external address and port.

## Why

By default, pf `nat-to` rules allocate a random outbound port for each distinct `src:port -> dst:port` UDP connection. This is hard NAT, which breaks STUN since the STUN server sees a source port that (most likely) won't match the port used for other destinations.

One workaround is to use [`static-port` pf.conf option][static-port], but this prevents multiple LAN hosts from establishing a connection to the same external host using the same local source port (the post-NAT `src:port` and `dst:port` would be the same, so both connections would match the same state entry).

By dynamically adding `nat-to` rules that match outbound STUN connections, pfnatd ensures that the same `internal-addr:port` is translated to the same `external-addr:port` regardless of the destination, effectively making pf behave as an easy NAT device.

Other solutions to the hard NAT problem are [NAT-PMP] and the newer [PCP] protocols. There are a few reasons why pfnatd focuses on the STUN approach:

* There is no server listening for incoming connections on the local network.
* pf does not open any new ports.
* Clients do not get to specify what ports to forward.

[Easy NAT]: https://tailscale.com/blog/how-nat-traversal-works#naming-our-nats
[rfc4787]: https://datatracker.ietf.org/doc/html/rfc4787#section-4
[pf]: https://man.openbsd.org/pf
[pflog]: https://man.openbsd.org/pflog
[STUN]: https://en.wikipedia.org/wiki/STUN
[static-port]: https://man.openbsd.org/pf.conf#static-port
[NAT-PMP]: https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol
[PCP]: https://en.wikipedia.org/wiki/Port_Control_Protocol

## Building on OpenBSD

```
doas pkg_add rust llvm
export LIBCLANG_PATH=/usr/local/llvm19/lib
cargo build
```

See [bindgen] documentation for more info.

[bindgen]: https://rust-lang.github.io/rust-bindgen/requirements.html#openbsd
