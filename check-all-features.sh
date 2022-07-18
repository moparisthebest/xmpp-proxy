#!/bin/bash
threads="$1"

set -euo pipefail

# if we have access to nproc, divide that by 2, otherwise use 1 thread by default
[ "$threads" == "" ] && threads=$(($(nproc || echo 2) / 2))

echo "threads: $threads"

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
    for proto in $(perms tls quic websocket)
    do
      for direction in $(perms c2s-incoming c2s-outgoing s2s-incoming s2s-outgoing)
      do
        for ca_roots in tls-ca-roots-native tls-ca-roots-bundled
        do
          echo $direction,$proto,$ca_roots$optional
        done
      done
    done
  done

  for optional in "" $(perms_optional logging systemd)
  do
    for proto in $(perms tls quic websocket)
    do
      echo c2s-incoming,$proto$optional
    done
  done
}

echo_cargo() {
  set -euo pipefail
  #echo cargo run "$@" -- -v
  #cargo run "$@" -- -v
  echo cargo check "$@"
  cargo check "$@"
}

#all_features | sort -u | wc -l; exit 0

export -f echo_cargo

echo_cargo

all_features | sort | xargs -n1 --max-procs=$threads bash -c 'echo_cargo --no-default-features --features "$@" || exit 255' _

echo good!
