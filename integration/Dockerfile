
# base image
FROM docker.io/library/archlinux AS base

ENV PACMAN_MIRROR https://burtrum.org/archlinux
ENV TZ=America/New_York

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    echo -e "Server = $PACMAN_MIRROR/\$repo/os/\$arch" > /etc/pacman.d/mirrorlist && \
    pacman -Syu --noconfirm --disable-download-timeout

# build some things
FROM base AS build

RUN pacman -S --noconfirm --disable-download-timeout --needed rust cargo git mercurial base-devel \
    lua52 lua52-expat lua52-filesystem lua52-sec lua52-socket \
    lua lua53 lua52 lua51 luarocks && \
    mkdir -p /build/{src,target}/ && \
    hg clone 'https://hg.prosody.im/prosody-modules/' /build/prosody-modules && rm -rf /build/prosody-modules/.hg && \
    git clone https://aur.archlinux.org/scansion-hg.git /build/scansion-hg && \
    git clone https://aur.archlinux.org/lua-cjson.git /build/lua-cjson && \
    usermod --expiredate= nobody && \
    chown -R nobody: /build/ && ls -lah /build/ && \
    cd /build/lua-cjson && su -m -s /bin/bash nobody makepkg && pacman -U --noconfirm --needed lua52-cjson-*.pkg.tar* && \
    cd /build/scansion-hg && su -m -s /bin/bash nobody makepkg

RUN pacman -S --noconfirm --disable-download-timeout --needed unbound gcc luarocks && luarocks --lua-version 5.2 install luaunbound && cp /usr/lib/lua/5.2/lunbound.so /build/

COPY ./Cargo.* ./build.rs /build/
COPY ./src/ /build/src/
#COPY ./target/ /build/target/

ARG BUILD=0

RUN if [ $BUILD -eq 0 ]; then cd /build && grep -v fuzz Cargo.toml > Cargo.toml.nofuzz && mv Cargo.toml.nofuzz Cargo.toml && cargo build --release; fi

# final image
FROM base

COPY --from=build /build/*/*.pkg.tar* /tmp/

RUN pacman -S --noconfirm --disable-download-timeout --needed bind nginx prosody lua52-sec ejabberd nss mkcert curl unbound && \
    usermod --expiredate= jabber && \
    pacman -U --noconfirm --needed /tmp/*.pkg.tar* && rm -f /tmp/*.pkg.tar* && \
    pacman -U --noconfirm --needed https://burtrum.org/archlinux/extra/os/x86_64/prosody-1%3A0.12.5-1-x86_64.pkg.tar.zst && \
    mkdir -p /opt/xmpp-proxy/prosody-modules/ /opt/prosody-modules/ /scansion && mkcert -install && \
    mkdir -p /etc/certs/ecdsa && cd /etc/certs/ecdsa && \
    mkcert -ecdsa -client -cert-file one.example.org.crt -key-file one.example.org.key one.example.org && \
    mkcert -ecdsa -client -cert-file two.example.org.crt -key-file two.example.org.key two.example.org && \
    mkcert -ecdsa -client -cert-file xp1.example.org.crt -key-file xp1.example.org.key xp1.example.org && \
    mkcert -ecdsa -client -cert-file xp2.example.org.crt -key-file xp2.example.org.key xp2.example.org && \
    mkcert -ecdsa -client -cert-file wildcard.crt        -key-file wildcard.key        '*.example.org' && \
    cp wildcard.crt legacy_ssl.crt && cp wildcard.key legacy_ssl.key && \
    cp wildcard.crt https.crt      && cp wildcard.key https.key && \
    mkdir -p /etc/certs/rsa && cd /etc/certs/rsa && \
    mkcert        -client -cert-file one.example.org.crt -key-file one.example.org.key one.example.org && \
    mkcert        -client -cert-file two.example.org.crt -key-file two.example.org.key two.example.org && \
    mkcert        -client -cert-file xp1.example.org.crt -key-file xp1.example.org.key xp1.example.org && \
    mkcert        -client -cert-file xp2.example.org.crt -key-file xp2.example.org.key xp2.example.org && \
    mkcert        -client -cert-file wildcard.crt        -key-file wildcard.key        '*.example.org' && \
    cp wildcard.crt legacy_ssl.crt && cp wildcard.key legacy_ssl.key && \
    cp wildcard.crt https.crt      && cp wildcard.key https.key && \
    chmod -R 777 /etc/certs/ && rm -rf /etc/prosody/certs && ln -sf /etc/certs/rsa /etc/prosody/certs

COPY --from=build /build/prosody-modules /opt/prosody-modules

COPY --from=build /usr/bin/true /build/target/release/xmpp-prox[y] /usr/bin/

COPY --from=build /build/lunbound.so /usr/lib/lua/5.2/lunbound.so

COPY ./integration/named.conf /etc/
COPY ./integration/00-no-tls/example.org.zone /var/named/
COPY ./integration/00-no-tls/prosody1.cfg.lua /etc/prosody/prosody.cfg.lua
COPY ./contrib/prosody-modules /opt/xmpp-proxy/prosody-modules
COPY ./integration/*.scs /scansion/

RUN mkdir -p /run/prosody/

ARG ECDSA=0

RUN if [ $ECDSA -ne 0 ]; then rm -rf /etc/prosody/certs && ln -sf /etc/certs/ecdsa /etc/prosody/certs; fi
