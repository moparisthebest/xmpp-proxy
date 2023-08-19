#!/bin/bash
set -exo pipefail

echo "starting build for TARGET $TARGET"

export CRATE_NAME=xmpp-proxy

SUFFIX=""

echo "$TARGET" | grep -E '^x86_64-pc-windows-gnu$' >/dev/null && SUFFIX=".exe"

# ring fails to compile here
echo "$TARGET" | grep -E '^(s390x|powerpc|mips|riscv64gc|.*solaris$)' >/dev/null && echo "$TARGET not supported in rustls" && exit 0

# running `docker system prune -af` after these because they are roughly every 25% through and my hard drive space is limited
echo "$TARGET" | grep -E  '^(armv7-unknown-linux-gnueabihf|x86_64-linux-android|mips-unknown-linux-gnu)$' >/dev/null && docker system prune -af

# mio fails to link here
echo "$TARGET" | grep -E  '^x86_64-unknown-netbsd$' >/dev/null && echo "$TARGET not supported in mio" && exit 0

# build binary
cross build --target $TARGET --release

# to check how they are built
file "target/$TARGET/release/${CRATE_NAME}$SUFFIX"

# if this commit has a tag, upload artifact to release
strip "target/$TARGET/release/${CRATE_NAME}$SUFFIX" || true # if strip fails, it's fine
mkdir -p release
cp "target/$TARGET/release/${CRATE_NAME}$SUFFIX" "release/${CRATE_NAME}-$TARGET$SUFFIX"

echo 'build success!'
exit 0
