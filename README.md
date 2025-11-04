# pfnatd

[Easy NAT] mode (aka [Endpoint-Independent Mapping][RFC 4787]) for OpenBSD [packet filter (pf)][pf]. The pfnatd daemon monitors outbound [STUN] ([RFC 8489]) traffic via [pflog] and adds `nat-to` rules to ensure that subsequent packets from the same source are translated to the same external address/port regardless of the destination. This allows UDP-based services to establish direct connections to peers without relays.

[Easy NAT]: https://tailscale.com/blog/how-nat-traversal-works#naming-our-nats
[RFC 4787]: https://datatracker.ietf.org/doc/html/rfc4787#section-4
[pf]: https://man.openbsd.org/pf
[STUN]: https://en.wikipedia.org/wiki/STUN
[RFC 8489]: https://datatracker.ietf.org/doc/html/rfc8489
[pflog]: https://man.openbsd.org/pflog

## Installing

```
doas pkg_add git llvm rust
cargo install --git https://github.com/mxk/pfnatd.git
```

## Usage

Add `anchor "pfnatd"` to your [pf.conf][anchors] before any other `nat-to` rules. Rules within the anchor use `match ... tag PFNATD`, which allows additional processing by the main ruleset and requires an explicit `pass` rule to apply the translation. For example:

```
anchor "pfnatd" out on egress
pass out quick tagged PFNATD
```

[anchors]: https://man.openbsd.org/pf.conf#ANCHORS

## Testing

pfnatd has a built-in STUN client for testing. Below are example results for a client behind an OpenBSD firewall.

Without pfnatd daemon running:

```
$ pfnatd stun stun.cloudflare.com
192.0.2.1:60389
$ pfnatd stun stun.l.google.com
192.0.2.1:54698
```

With pfnatd daemon running:

```
$ pfnatd stun stun.cloudflare.com
192.0.2.1:53203
$ pfnatd stun stun.l.google.com
192.0.2.1:53203
```

## Details

By default, pf `nat-to` rules allocate a random outbound port for each distinct source/destination pair. This is hard NAT, which breaks STUN because the STUN server sees a source port that (most likely) won't match the port used for any other destination(s).

One workaround is to use the [`static-port` option][static-port], but this prevents multiple LAN hosts from establishing a connection to the same destination using the same local source port. The post-NAT `src:port` and `dst:port` would be the identical, so both connections would match the same pf state entry.

By dynamically adding `nat-to` rules in response to STUN traffic, pfnatd allows the initial random port assigned by pf to be used for all other destinations from the same LAN `src:port` client. This effectively makes pf behave as an easy NAT device, while still allowing any number of LAN clients to connect to the same destination.

Other solutions to the hard NAT problem, not counting manual rule management, are [UPnP], [NAT-PMP], and [PCP] protocols. There are a few reasons why pfnatd uses the STUN approach:

1. It is transparent and passive. There is no server listening for incoming connections on the local network.
2. It is more secure. Rules are added only to translate outbound traffic rather than open any inbound ports. Inbound traffic is only allowed implicitly by matching state established by outbound traffic.
3. Malicious clients cannot control external port assignment or open any services to the entire internet.

[static-port]: https://man.openbsd.org/pf.conf#static-port
[UPnP]: https://en.wikipedia.org/wiki/Universal_Plug_and_Play
[NAT-PMP]: https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol
[PCP]: https://en.wikipedia.org/wiki/Port_Control_Protocol

### Rule overview

The following rules are added to the `pfnatd` anchor:

`match out log (matches) proto udp to port 3478`

This static rule allows pfnatd to identify new STUN traffic. It assumes that the main ruleset contains a `pass ... nat-to ...` rule, which creates the initial state for the client. This is logged to [pflog] and translated to the following dynamic rule:

`match out on <iface> proto udp from <src-ip> port <src-port> nat-to <nat-ip> port <nat-port> tag PFNATD`

This rule is added for each unique STUN request and persists as long as there is at least one matching state. Source and NAT addresses are obtained from the packets logged by the first rule. The client application must implement a keep-alive mechanism either by repeating STUN requests or by exchanging packets with another endpoint in order to keep the state and this rule active.

## Known Issues

* A race condition exists if the client sends multiple concurrent STUN requests to different servers. By the time pfnatd has added a `nat-to` rule for the first requests, other requests may have created additional states using different outbound translations. When pfnatd detects different translations for the same source, it kills any states that do not match the existing rule, causing those responses to be blocked. This is safe to do because STUN operates on a best-effort basis and must tolerate lost response packets.
