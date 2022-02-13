
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
    lua52 lua52-expat lua52-filesystem lua52-sec lua52-socket && \
    mkdir -p /build/{src,target}/ && \
    hg clone 'https://hg.prosody.im/prosody-modules/' /build/prosody-modules && rm -rf /build/prosody-modules/.hg && \
    git clone https://aur.archlinux.org/scansion-hg.git /build/scansion-hg && \
    git clone https://aur.archlinux.org/lua52-cjson.git /build/lua52-cjson && \
    chown -R git: /build/ && ls -lah /build/ && \
    cd /build/lua52-cjson && su -m -s /bin/bash git makepkg && pacman -U --noconfirm --needed lua52-cjson-*.pkg.tar* && \
    cd /build/scansion-hg && su -m -s /bin/bash git makepkg

COPY ./Cargo.* /build/
COPY ./src/ /build/src/
#COPY ./target/ /build/target/

ARG BUILD=0

RUN if [ $BUILD -eq 0 ]; then cd /build && cargo build --release; fi

# final image
FROM base

COPY --from=build /build/*/*.pkg.tar* /tmp/

RUN pacman -S --noconfirm --disable-download-timeout --needed bind nginx prosody lua52-sec nss mkcert curl && \
    pacman -U --noconfirm --needed /tmp/*.pkg.tar* && rm -f /tmp/*.pkg.tar* && \
    mkdir -p /opt/xmpp-proxy/prosody-modules/ /opt/prosody-modules/ /scansion && mkcert -install && \
    mkdir -p /etc/certs/ecdsa && cd /etc/certs/ecdsa && \
    mkcert -ecdsa -cert-file one.example.org.crt -key-file one.example.org.key one.example.org && \
    mkcert -ecdsa -cert-file two.example.org.crt -key-file two.example.org.key two.example.org && \
    mkcert -ecdsa -cert-file xp1.example.org.crt -key-file xp1.example.org.key xp1.example.org && \
    mkcert -ecdsa -cert-file xp2.example.org.crt -key-file xp2.example.org.key xp2.example.org && \
    mkcert -ecdsa -cert-file wildcard.crt        -key-file wildcard.key        '*.example.org' && \
    cp wildcard.crt legacy_ssl.crt && cp wildcard.key legacy_ssl.key && \
    cp wildcard.crt https.crt      && cp wildcard.key https.key && \
    mkdir -p /etc/certs/rsa && cd /etc/certs/rsa && \
    mkcert        -cert-file one.example.org.crt -key-file one.example.org.key one.example.org && \
    mkcert        -cert-file two.example.org.crt -key-file two.example.org.key two.example.org && \
    mkcert        -cert-file xp1.example.org.crt -key-file xp1.example.org.key xp1.example.org && \
    mkcert        -cert-file xp2.example.org.crt -key-file xp2.example.org.key xp2.example.org && \
    mkcert        -cert-file wildcard.crt        -key-file wildcard.key        '*.example.org' && \
    cp wildcard.crt legacy_ssl.crt && cp wildcard.key legacy_ssl.key && \
    cp wildcard.crt https.crt      && cp wildcard.key https.key && \
    chmod -R 777 /etc/certs/ && rm -rf /etc/prosody/certs && ln -sf /etc/certs/rsa /etc/prosody/certs

COPY --from=build /build/prosody-modules /opt/prosody-modules

COPY --from=build /usr/bin/true /build/target/release/xmpp-prox[y] /usr/bin/

COPY ./integration/named.conf /etc/
COPY ./integration/00-no-tls/example.org.zone /var/named/
COPY ./integration/00-no-tls/prosody1.cfg.lua /etc/prosody/prosody.cfg.lua
COPY ./contrib/prosody-modules /usr/lib/prosody/modules
COPY ./integration/*.scs /scansion/

ARG ECDSA=0

RUN if [ $ECDSA -ne 0 ]; then rm -rf /etc/prosody/certs && ln -sf /etc/certs/ecdsa /etc/prosody/certs; fi
