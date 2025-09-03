#!/bin/bash
threads="$1"
shift
clean_after_num_builds="$1"

set -euo pipefail

# if we have access to nproc, divide that by 2, otherwise use 1 thread by default
[ "$threads" == "" ] && threads=$(($(nproc || echo 2) / 2))

# 50 is about 1.5gb, ymmv
[ "$clean_after_num_builds" == "" ] && clean_after_num_builds=50

export clean_after_num_builds

echo "threads: $threads"
echo "clean_after_num_builds: $clean_after_num_builds"

export RUSTFLAGS=-Awarnings

show() {
    local -a results=()
    let idx=$2
    for (( j = 0; j < $1; j++ )); do
        if (( idx % 2 )); then results=("${results[@]}" "${list[$j]}"); fi
        let idx\>\>=1
    done
    echo "${results[@]}"
}

perm_lines() {
  list=($@)
  let n=${#list[@]}
  for (( i = 1; i < 2**n; i++ )); do
      show $n $i
  done
}

perms() {
  perm_lines "$@" | tr ' ' ',' | sort -u
}

perms_optional() {
   perm_lines "$@" | tr ' ' ',' | sort -u | sed 's/^/,/'
}

all_features() {
  for optional in "" $(perms_optional logging systemd)
  do
    for proto in $(perms tls quic websocket webtransport)
    do
      for direction in $(perms c2s-incoming c2s-outgoing s2s-incoming s2s-outgoing)
      do
        for ca_roots in tls-ca-roots-native tls-ca-roots-bundled
        do
          # tls-aws-lc-rs-fips requires Go
          for provider in tls-aws-lc-rs tls-ring
          do
            echo $direction,$proto,$ca_roots,$provider$optional
          done
        done
      done
    done
  done

  for optional in "" $(perms_optional logging systemd)
  do
    for proto in $(perms tls quic websocket webtransport)
    do
      # tls-aws-lc-rs-fips requires Go
      for provider in tls-aws-lc-rs tls-ring
      do
        echo c2s-incoming,$provider,$proto$optional
      done
    done
  done
}

echo_cargo() {
  set -euo pipefail
  #echo cargo run "$@" -- -v
  #cargo run "$@" -- -v
  echo cargo check "$@"
  flock -s /tmp/xmpp-proxy-check-all-features.lock cargo check "$@"
  ret=$?
  if [ $ret -ne 0 ]
  then
    echo "command failed: cargo check $@"
  fi
  (
    flock -x 200
    # now we are under an exclusive lock
    count=$(cat /tmp/xmpp-proxy-check-all-features.count)
    count=$(( count + 1 ))
    if [ $count -ge $clean_after_num_builds ]
    then
      echo cargo clean
      cargo clean
      count=0
    fi
    echo $count > /tmp/xmpp-proxy-check-all-features.count

  ) 200>/tmp/xmpp-proxy-check-all-features.lock
  return $ret
}

#all_features | sort -u | wc -l; exit 0

export -f echo_cargo

echo 0 > /tmp/xmpp-proxy-check-all-features.count

echo_cargo

all_features | sort | xargs -n1 --max-procs=$threads bash -c 'echo_cargo --no-default-features --features "$@" || exit 255' _

echo good!


