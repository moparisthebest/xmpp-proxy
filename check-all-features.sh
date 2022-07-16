#!/bin/bash
set -euo pipefail

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
  perm_lines "$@" | tr ' ' ',' | sort -u | tr '\n' ' '
}

echo_cargo() {
  #echo cargo run "$@" -- -v
  #cargo run "$@" -- -v
  echo cargo check "$@"
  cargo check "$@"
}

echo_cargo

for optional in "" ",logging"
do
  for proto in $(perms tls quic websocket)
  do
    for direction in $(perms c2s-incoming c2s-outgoing s2s-incoming s2s-outgoing)
    do
      for ca_roots in tls-ca-roots-native tls-ca-roots-bundled
      do
        echo_cargo --no-default-features --features $direction,$proto,$ca_roots$optional
      done
    done
  done
done

for optional in "" ",logging"
do
  for proto in $(perms tls quic websocket)
  do
    echo_cargo --no-default-features --features c2s-incoming,$proto$optional
  done
done

echo good!
