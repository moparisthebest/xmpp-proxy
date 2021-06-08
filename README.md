# xmpp-proxy

[![Build Status](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/badge/icon%3Fstyle=plastic)](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/)

xmpp-proxy is a reverse proxy and outgoing proxy for XMPP servers and clients, providing STARTTLS, 
[Direct TLS](https://xmpp.org/extensions/xep-0368.html), and [QUIC](https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport)
connectivity to plain-text XMPP servers and clients and limiting stanza sizes without an XML parser.

xmpp-proxy in reverse proxy (incoming) mode will:
  1. listen on any number of interfaces/ports
  2. accept any STARTTLS, Direct TLS, or QUIC c2s or s2s connections from the internet
  3. terminate TLS
  4. connect them to a local real XMPP server over plain-text TCP
  5. send the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) v1 header if configured, so the
  XMPP server knows the real client IP
  6. limit incoming stanza sizes as configured

xmpp-proxy in outgoing mode will:
  1. listen on any number of interfaces/ports
  2. accept any plain-text TCP connection from a local XMPP server or client
  3. look up the required SRV records
  4. connect to a real XMPP server across the internet over STARTTLS, Direct TLS, or QUIC
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
  * put your TLS key/cert in `/etc/xmpp-proxy/`, if your key has "RSA PRIVATE KEY" in it, change that to "PRIVATE KEY":
    `sed -i 's/RSA PRIVATE KEY/PRIVATE KEY/' /etc/xmpp-proxy/le.key`
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
"secure_interfaces";
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

-- xmpp-proxy outgoing is listening on this port, make all outgoing s2s connections directly to here
s2s_outgoing_proxy = { "127.0.0.1", 15270 }

-- trust connections coming from these IPs
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
-- trust connections coming from these IPs
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

xmpp-proxy has 3 compile-time features:
  1. `incoming` - enables `incoming_listen` config option for reverse proxy STARTTLS/TLS
  2. `outgoing` - enables `outgoing_listen` config option for outgoing proxy STARTTLS/TLS
  3. `quic` - enables `quic_listen` config option for reverse proxy QUIC, and QUIC support for `outgoing` if it is enabled

So to build only supporting reverse proxy STARTTLS/TLS, no QUIC, run: `cargo build --release --no-default-features --features incoming`
To build a reverse proxy only, but supporting all of STARTTLS/TLS/QUIC, run: `cargo build --release --no-default-features --features incoming,quic`

####  License
GNU/AGPLv3 - Check LICENSE.md for details

Thanks [rxml](https://github.com/horazont/rxml) for afl-fuzz seeds

#### todo
  1. sasl external for s2s, initiating and receiving
  2. better debug log output
  3. websocket incoming and outgoing, maybe even for s2s
