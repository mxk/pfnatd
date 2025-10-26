# pfnatd

[Easy NAT] mode ([Endpoint-Independent Mapping][rfc4787]) for OpenBSD [pf]. The pfnatd daemon monitors packets via [pflog]. When it sees outbound [STUN] traffic, it adds a `nat-to` rule to ensure that subsequent packets from the same source are translated to the same external address and port. This allows UDP-based services to establish direct connections to peers without relays.

[Easy NAT]: https://tailscale.com/blog/how-nat-traversal-works#naming-our-nats
[rfc4787]: https://datatracker.ietf.org/doc/html/rfc4787#section-4
[pf]: https://man.openbsd.org/pf
[pflog]: https://man.openbsd.org/pflog
[STUN]: https://en.wikipedia.org/wiki/STUN

## Installing on OpenBSD

```
doas pkg_add git llvm rust
cargo install --git https://github.com/mxk/pfnatd.git
```

## Usage

Add `anchor "pfnatd"` to your [pf.conf][anchors] before any other `nat-to` rules.

[anchors]: https://man.openbsd.org/pf.conf#ANCHORS

## Why

By default, pf `nat-to` rules allocate a random outbound port for each distinct `src:port -> dst:port` UDP connection. This is hard NAT, which breaks STUN because the STUN server sees a source port that (most likely) won't match the port used for any other destination(s).

One workaround is to use the [`static-port` option][static-port], but this prevents multiple LAN hosts from establishing a connection to the same external host using the same local source port (the post-NAT `src:port` and `dst:port` would be the identical, so both connections would match the same pf state entry).

By dynamically adding `nat-to` rules that match STUN replies, pfnatd ensures that the same `internal-addr:port` is translated to the same `external-addr:port` regardless of the destination, effectively making pf behave as an easy NAT device.

Other solutions to the hard NAT problem are [UPnP], [NAT-PMP], and [PCP] protocols. There are a few reasons why pfnatd uses the STUN approach:

1. It is transparent and passive. There is no server listening for incoming connections on the local network.
2. It is more secure. Rules are added only to translate outbound traffic rather than opening any inbound ports, potentially to the entire internet.
3. Malicious clients do not control external ports.

[static-port]: https://man.openbsd.org/pf.conf#static-port
[UPnP]: https://en.wikipedia.org/wiki/Universal_Plug_and_Play
[NAT-PMP]: https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol
[PCP]: https://en.wikipedia.org/wiki/Port_Control_Protocol

## Known Issues

* A race condition exists when the client sends multiple STUN requests to different servers quickly. By the time pfnatd has added a `nat-to` rule for the first packet, subsequent packets may have created additional states using different outbound ports. A future version may handle this by removing pf states that do not match the newly added rule.
