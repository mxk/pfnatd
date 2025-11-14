# pfnatd

[![Crates.io Version](https://img.shields.io/crates/v/pfnatd?style=for-the-badge)
](https://crates.io/crates/pfnatd)
[![Crates.io License](https://img.shields.io/crates/l/pfnatd?style=for-the-badge)
](https://choosealicense.com/licenses/mpl-2.0/)

[Easy NAT] mode (aka [Endpoint-Independent Mapping][RFC 4787]) for OpenBSD [packet filter (pf)][pf(4)]. The pfnatd daemon monitors outbound [STUN] ([RFC 8489]) traffic via [pflog(4)] and adds `nat-to` rules to ensure that subsequent packets from the same source are translated to the same external address/port regardless of the destination. This allows UDP-based services to establish direct connections to peers without relays.

[Easy NAT]: https://tailscale.com/blog/how-nat-traversal-works#naming-our-nats
[RFC 4787]: https://datatracker.ietf.org/doc/html/rfc4787#section-4
[pf(4)]: https://man.openbsd.org/pf.4
[STUN]: https://en.wikipedia.org/wiki/STUN
[RFC 8489]: https://datatracker.ietf.org/doc/html/rfc8489
[pflog(4)]: https://man.openbsd.org/pflog.4

## Installation on OpenBSD 7.8+

1. Add `anchor "pfnatd"` to your [pf.conf][anchors] before any other `nat-to` rules and reload pf. [Rules](#rule-overview) within the anchor use `match ... tag PFNATD`, which allows additional processing by the main ruleset and requires an explicit `pass` rule to apply the translation. For example:

   ```
   anchor "pfnatd" out on egress
   pass out quick tagged PFNATD
   ```

2. Build, install, and start pfnatd daemon:

   ```
   doas pkg_add git llvm rust
   cargo install pfnatd
   doas ~/.cargo/bin/pfnatd install
   doas rcctl start pfnatd
   ```

When started via the [rc.d(8)] script, pfnatd logs messages to [syslogd(8)] using `LOG_DAEMON` facility. Use `--log-level` option to control verbosity:

```
doas rcctl set pfnatd flags --log-level=trace
```

Run `pfnatd help` to see additional commands and options.

[anchors]: https://man.openbsd.org/pf.conf.5#ANCHORS
[rc.d(8)]: https://man.openbsd.org/rc.d.8
[syslogd(8)]: https://man.openbsd.org/syslogd.8

## Testing

pfnatd has a built-in STUN client for testing. Below are example outputs for a client behind an OpenBSD firewall.

Without pfnatd daemon running (two different random ports):

```
$ pfnatd stun stun.cloudflare.com
192.0.2.1:60389
$ pfnatd stun stun.l.google.com
192.0.2.1:54698
```

With pfnatd daemon running (same random port):

```
$ pfnatd stun stun.cloudflare.com
192.0.2.1:53203
$ pfnatd stun stun.l.google.com
192.0.2.1:53203
```

It is recommended to run `doas pfnatd --log-level=trace` while testing to see which packets are being logged to [pflog(4)].

## Details

By default, pf `nat-to` rules allocate a random outbound port for each distinct source/destination pair. This is hard NAT, which breaks STUN because the STUN server sees a source port that (most likely) won't match the port used for any other destination(s).

One workaround is to use the [`static-port` option][static-port], but this prevents multiple LAN hosts from establishing a connection to the same destination using the same local source port. The post-NAT `src:port` and `dst:port` would be the identical, so both connections would match the same pf state entry.

By dynamically adding `nat-to` rules in response to STUN traffic, pfnatd allows the initial random port assigned by pf to be used for all other destinations from the same LAN `src:port` client. This effectively makes pf behave as an easy NAT device, while still allowing any number of LAN clients to connect to the same destination.

Other solutions to the hard NAT problem, not counting manual rule management, are [UPnP], [NAT-PMP], and [PCP] protocols. There are a few reasons why pfnatd uses the STUN approach:

1. It is transparent and passive. There is no server listening for incoming connections on the local network.
2. It is more secure. Rules are added only to translate outbound traffic rather than open any inbound ports. Inbound traffic is only allowed implicitly by matching state established by outbound traffic.
3. Malicious clients cannot control external port assignment or open any services to the entire internet.

[static-port]: https://man.openbsd.org/pf.conf.5#static-port
[UPnP]: https://en.wikipedia.org/wiki/Universal_Plug_and_Play
[NAT-PMP]: https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol
[PCP]: https://en.wikipedia.org/wiki/Port_Control_Protocol

### Rule overview

The following rules are added to the `pfnatd` anchor:

`match out log (matches, to pflog1) proto udp`

This static rule allows pfnatd to identify STUN requests. By default, pfnatd uses `pflog1` interface, which is created automatically, to avoid interfering with [pflogd(8)] operation. This rule assumes that the main ruleset contains a catch-all `pass ... nat-to ...` rule that creates the initial state for the client, is logged to [pflog(4)], and translated to the following dynamic rule:

`match out on <iface> proto udp from <src-ip> port <src-port> nat-to <nat-ip> port <nat-port> tag PFNATD`

This rule is added for each unique STUN request and persists as long as there is at least one matching state. Source and NAT addresses are obtained from the packets logged by the first rule. The client application must implement a keep-alive mechanism either by repeating STUN requests or by exchanging packets with another endpoint in order to keep the state and this rule active.

While many STUN servers use the default UDP port 3478, some do not. For example, `stun.cloudflare.com` allows requests on port 53 and `stun.l.google.com` on port 19302. For this reason, the first match rule does not restrict the port. Instead, pfnatd inspects UDP data to only match STUN binding requests that contain [RFC 5389] magic cookie. If stricter filtering is required, restrictions can be added to the anchor:

`anchor "pfnatd" out on egress to port 3478`

[pflogd(8)]: https://man.openbsd.org/pflogd.8
[RFC 5389]: https://datatracker.ietf.org/doc/html/rfc5389

## Known Issues

A race condition exists if the client sends multiple concurrent STUN requests to different servers. By the time pfnatd has added a `nat-to` rule for the first requests, other requests may have created additional states using different outbound translations. When pfnatd detects different translations for the same source, it kills any states that do not match the existing rule, causing those responses to be blocked. This is safe to do because STUN operates on a best-effort basis and must tolerate lost response packets.
