# xmpp-proxy

[![Build Status](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/badge/icon%3Fstyle=plastic)](https://ci.moparisthe.best/job/moparisthebest/job/xmpp-proxy/job/master/)

xmpp-proxy is a reverse proxy for XMPP servers, providing STARTTLS and TLS over plain-text XMPP connections
and limiting stanza sizes without an XML parser.

xmpp-proxy will listen on any number of interfaces/ports and accept any STARTTLS or [Direct TLS](https://xmpp.org/extensions/xep-0368.html) 
c2s or s2s connections, terminate TLS, and connect them to a real XMPP server, limiting stanza sizes as configured.

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

Add these to modules_enabled:
```
"secure_interfaces";
"net_proxy";
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
s2s_ports = {15269}
```

Copy prosody's TLS key to `/etc/xmpp-proxy/le.key` and TLS cert to `/etc/xmpp-proxy/fullchain.cer`, and use the provided
`xmpp-proxy.toml` configuration as-is.

####  License
GNU/AGPLv3 - Check LICENSE.md for details
