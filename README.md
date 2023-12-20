
<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/moparisthebest/xmpp-proxy/master/contrib/logo/xmpp_proxy_color.png" alt="logo" width="200">
  <br>
  xmpp-proxy
  <br>
  <br>
</h1>

[![Build Status](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/badge/icon%3Fstyle=plastic)](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/)

xmpp-proxy is a reverse proxy and outgoing proxy for XMPP servers and clients, providing [STARTTLS], [Direct TLS], [QUIC],
[WebSocket C2S], [WebSocket S2S], and [WebTransport] connectivity to plain-text XMPP servers and clients and limiting stanza sizes without an XML parser.

xmpp-proxy in reverse proxy (incoming) mode will:
  1. listen on any number of interfaces/ports
  2. accept any STARTTLS, Direct TLS, QUIC, WebSocket, or WebTransport c2s or s2s connections from the internet
  3. terminate TLS
  4. for s2s require a client cert and validate it correctly (using CAs, host-meta, host-meta2, and POSH) for SASL EXTERNAL auth
  5. connect them to a local real XMPP server over plain-text TCP
  6. send the [PROXY protocol] v1 header if configured, so the XMPP server knows the real client IP
  7. limit incoming stanza sizes as configured

xmpp-proxy in outgoing mode will:
  1. listen on any number of interfaces/ports
  2. accept any plain-text TCP or WebSocket connection from a local XMPP server or client
  3. look up the required SRV, [host-meta], [host-meta2], and [POSH] records
  4. connect to a real XMPP server across the internet over STARTTLS, Direct TLS, QUIC, WebSocket, or WebTransport
  5. fallback to next SRV target or defaults as required to fully connect
  6. perform all the proper required certificate validation logic
  7. limit incoming stanza sizes as configured

#### Installation
  * `cargo install xmpp-proxy`
  * Download static binary from [xmpp-proxy](https://code.moparisthebest.com/moparisthebest/xmpp-proxy/releases)
    or [xmpp-proxy (github mirror)](https://github.com/moparisthebest/xmpp-proxy/releases)
  * your favorite package manager

#### Configuration
  * `mkdir /etc/xmpp-proxy/ && cp xmpp-proxy.toml /etc/xmpp-proxy/`
  * edit `/etc/xmpp-proxy/xmpp-proxy.toml` as needed, file is annotated clearly with comments
  * put your TLS key/cert in `/etc/xmpp-proxy/`
  * Example systemd unit is provided in xmpp-proxy.service and locks it down with bare minimum permissions.  Need to
    set the permissions correctly: `chown -Rv 'systemd-network:' /etc/xmpp-proxy/`
  * start xmpp-proxy: `Usage: xmpp-proxy [/path/to/xmpp-proxy.toml (default /etc/xmpp-proxy/xmpp-proxy.toml]`

#### How do I adapt my running Prosody config to use this instead?

You have 2 options here, use xmpp-proxy as only a reverse proxy, or as both reverse and outgoing proxy, I'll cover both:

###### Reverse proxy and outgoing proxy

In this mode both prosody doesn't need to do any TLS at all, so it needs no certs. xmpp-proxy need proper TLS
certificates, move prosody's TLS key to `/etc/xmpp-proxy/le.key` and TLS cert to `/etc/xmpp-proxy/fullchain.cer`, and
use the provided `xmpp-proxy.toml` configuration as-is.

Edit `/etc/prosody/prosody.cfg.lua`, Add these to modules_enabled:
```
"net_proxy";
"s2s_outgoing_proxy";
```
Until prosody-modules is updated, use my new module [mod_s2s_outgoing_proxy.lua](https://www.moparisthebest.com/mod_s2s_outgoing_proxy.lua).

Add this config:
```
-- only need to listen on localhost
interfaces = { "127.0.0.1" }

-- we don't need prosody doing any encryption, xmpp-proxy does this now
-- these are likely set to true somewhere in your file, find them, make them false
-- you can also remove all certificates from your config
s2s_require_encryption = false
s2s_secure_auth = false
c2s_require_encryption = false
allow_unencrypted_plain_auth = true

-- xmpp-proxy outgoing is listening on this port, make all outgoing s2s connections directly to here
s2s_outgoing_proxy = { "127.0.0.1", 15270 }

-- handle PROXY protocol on these ports
proxy_port_mappings = {
    [15222] = "c2s",
    [15269] = "s2s"
}

-- don't listen on any normal c2s/s2s ports (xmpp-proxy listens on these now)
-- you might need to comment these out further down in your config file if you set them
c2s_ports = {}
legacy_ssl_ports = {}
-- you MUST have at least one s2s_ports defined if you want outgoing S2S to work, don't ask.. 
s2s_ports = {15268}
```

###### Reverse proxy only, prosody makes outgoing connections directly itself

In this mode both prosody and xmpp-proxy need proper TLS certificates, copy prosody's TLS key to `/etc/xmpp-proxy/le.key`
and TLS cert to `/etc/xmpp-proxy/fullchain.cer`, and use the provided `xmpp-proxy.toml` configuration as-is.

Edit `/etc/prosody/prosody.cfg.lua`, Add these to modules_enabled:
```
"net_proxy";
"secure_interfaces";
```
Until prosody-modules is updated, use my patched version of [mod_secure_interfaces.lua](https://www.moparisthebest.com/mod_secure_interfaces.lua)
which also works for s2s.

Add this config:
```
-- trust connections coming to these IPs
secure_interfaces = { "127.0.0.1", "::1" }

-- handle PROXY protocol on these ports
proxy_port_mappings = {
    [15222] = "c2s",
    [15269] = "s2s"
}

-- don't listen on any normal c2s/s2s ports (xmpp-proxy listens on these now)
-- you might need to comment these out further down in your config file if you set them
c2s_ports = {}
legacy_ssl_ports = {}
-- you MUST have at least one s2s_ports defined if you want outgoing S2S to work, don't ask.. 
s2s_ports = {15268}
```

#### Customize the build

If you are a grumpy power user who wants to build xmpp-proxy with exactly the features you want, nothing less, nothing
more, this section is for you!

xmpp-proxy has multiple compile-time features, some of which are required, they are grouped as such:

choose between 1-4 directions:
  1. `c2s-incoming` - enables a server to accept incoming c2s connections
  2. `c2s-outgoing` - enables a client to make outgoing c2s connections
  3. `s2s-incoming` - enables a server to accept incoming s2s connections
  4. `s2s-outgoing` - enables a server to make outgoing s2s connections

choose between 1-4 transport protocols:
  1. `tls` - enables STARTTLS/TLS support
  2. `quic` - enables QUIC support
  3. `websocket` - enables WebSocket support, also enables TLS incoming support if the appropriate directions are enabled
  4. `webtransport` - enables WebTransport support, also enables QUIC

choose exactly 1 of these methods to get trusted CA roots, not needed if only `c2s-incoming` is enabled:
  1. `tls-ca-roots-native` - reads CA roots from operating system
  2. `tls-ca-roots-bundled` - bundles CA roots into the binary from the `webpki-roots` project

choose any of these optional features:
  1. `logging` - enables configurable logging

So to build only supporting reverse proxy STARTTLS/TLS, no QUIC, run: `cargo build --release --no-default-features --features c2s-incoming,s2s-incoming,tls`
To build a reverse proxy only, but supporting all of STARTTLS/TLS/QUIC, run: `cargo build --release --no-default-features --features c2s-incoming,s2s-incoming,tls,quic`

#### Development

1. `check-all-features.sh` is used to check compilation with all supported feature permutations
2. `integration/test.sh` uses [Rootless podman](https://wiki.archlinux.org/title/Podman#Rootless_Podman) to run many tests
    through xmpp-proxy on a real network with real dns, web, and xmpp servers, all of these should pass before pushing commits,
    and write new tests to cover new functionality.
3. To submit code changes submit a PR on [github](https://github.com/moparisthebest/xmpp-proxy) or
   [code.moparisthebest.com](https://code.moparisthebest.com/moparisthebest/xmpp-proxy) or send me a patch via email,
   XMPP, fediverse, or carrier pigeon.

####  License
GNU/AGPLv3 - Check LICENSE.md for details

Thanks [rxml](https://github.com/horazont/rxml) for afl-fuzz seeds

#### Todo
  1. seamless Tor integration, connecting to and from .onion domains
  2. Write WebTransport XEP
  3. Document systemd activation support
  4. Document use-as-a-library support

[STARTTLS]: https://datatracker.ietf.org/doc/html/rfc6120#section-5
[Direct TLS]: https://xmpp.org/extensions/xep-0368.html
[QUIC]: https://xmpp.org/extensions/xep-0467.html
[WebSocket C2S]: https://datatracker.ietf.org/doc/html/rfc7395
[WebSocket S2S]: https://xmpp.org/extensions/xep-0468.html
[WebTransport]: https://www.w3.org/TR/webtransport/
[POSH]: https://datatracker.ietf.org/doc/html/rfc7711
[host-meta]: https://xmpp.org/extensions/xep-0156.html
[host-meta2]: https://xmpp.org/extensions/inbox/host-meta-2.html
[PROXY protocol]: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
