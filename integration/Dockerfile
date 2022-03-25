
# docker stop foo; docker build -t foo . && docker run -d --rm -it --hostname foo.ppd --name foo -v /sys/fs/cgroup:/sys/fs/cgroup:ro --privileged foo && docker exec -it foo bash
# docker stop foo; docker build -t foo . && docker run -d --rm -it --hostname foo.ppd --name foo -v /sys/fs/cgroup:/sys/fs/cgroup:ro --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH foo && docker exec -it foo bash

# docker stop foo; docker build -t foo . && docker run -d --rm -it --hostname foo.ppd --name foo -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /home/mopar/devel/server-configs-git:/u01/gcl/server-configs:ro --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH --dns='172.17.179.240' --dns='172.30.179.225' --dns-search='labs.ppdi.local' --dns-search='mrli.ppdi.com' --dns-search='wilm.ppdi.com' --dns-search='austin.ppdi.com' foo && docker exec -it foo bash

# to run existing tag built on jenkins locally:
# docker run -d --restart=always -it --hostname docker.ppd --name docker -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /home/service-connexion/server-configs:/u01/gcl/server-configs:ro --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH --dns='172.17.179.240' --dns='172.30.179.225' --dns-search='labs.ppdi.local' --dns-search='mrli.ppdi.com' --dns-search='wilm.ppdi.com' --dns-search='austin.ppdi.com' registry.gcl.ppdi.com/connexion:docker

# docker build -t registry.gcl.ppdi.com/connexion-base:docker .

# docker stop foo
# docker rmi foo

# to enter running container
# docker exec -it foo bash
# docker exec -it foo su - service-connexion

# to update the archlinux base image run the update-archlinux-base job
#       http://vhhsxbld01.mrli.ppdi.com/jenkins/view/All/job/update-archlinux-base/
# and inspect the build output to find the latest tag

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

RUN pacman -S --noconfirm --disable-download-timeout --needed bind nginx prosody lua52-sec ejabberd nss mkcert curl && \
    pacman -U --noconfirm --needed /tmp/*.pkg.tar* && rm -f /tmp/*.pkg.tar* && \
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

COPY ./integration/named.conf /etc/
COPY ./integration/00-no-tls/example.org.zone /var/named/
COPY ./integration/00-no-tls/prosody1.cfg.lua /etc/prosody/prosody.cfg.lua
COPY ./contrib/prosody-modules /opt/xmpp-proxy/prosody-modules
COPY ./integration/*.scs /scansion/

ARG ECDSA=0

RUN if [ $ECDSA -ne 0 ]; then rm -rf /etc/prosody/certs && ln -sf /etc/certs/ecdsa /etc/prosody/certs; fi
