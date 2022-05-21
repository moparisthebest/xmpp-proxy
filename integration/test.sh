#!/bin/sh
set -euxo pipefail

ipv4='192.5'

# change to this directory
cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

usage() { echo "Usage: $0 [-i 192.5] [-d] [-r] [-b] [-n]" 1>&2; exit 1; }

build=0
build_args=''
img='xmpp-proxy-test'
xmpp_proxy_bind=''
run_blocked=0
rebuild_image=0
ecdsa=0
threads=1
while getopts ":it:drbeno" o; do
    case "${o}" in
        i)
            ipv4=${OPTARG}
            ;;
        t)
            threads=${OPTARG}
            ;;
        d)
            build=1
            xmpp_proxy_bind="-v $PWD/../target/debug/xmpp-proxy:/usr/bin/xmpp-proxy:ro"
            ;;
        r)
            build=1
            build_args='--release'
            xmpp_proxy_bind="-v $PWD/../target/release/xmpp-proxy:/usr/bin/xmpp-proxy:ro"
            ;;
        e)
            ecdsa=1
            ;;
        b)
            run_blocked=1
            ;;
        n)
            podman image rm -f "$img" "$img-dev" "$img-dev-ecdsa"
            exit $?
            ;;
        o)
            rebuild_image=1
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

[ $build -eq 1 ] && img="$img-dev"
[ $ecdsa -eq 1 ] && img="$img-ecdsa"

rm -rf /tmp/xp-logs/
mkdir -p /tmp/xp-logs/

success=/tmp/xp-logs/success.txt
error=/tmp/xp-logs/error.txt
skipped=/tmp/xp-logs/skipped.txt

run_container() {
    set +x
    network_name="$1"
    shift
    num="$1"
    shift
    args=()
    if [ "$1" == "-d" ]
    then
        args+=("-d")
        shift
    fi
    while [ "$1" == "-v" -o "$1" == "-w" ]
    do
        args+=("$1")
        shift
        args+=("$1")
        shift
    done
    ip="$1"
    shift
    name="$1"
    shift
    
    set -x
    podman run "${args[@]}" --rm --log-driver=k8s-file "--log-opt=path=/tmp/xp-logs/$dir-$name.log" --network "$network_name" --dns-search example.org --dns "$ipv4.$num.10" --hostname "$name" --name "$num-$name" --ip "$ipv4.$num.$ip" "$img" "$@"
}

cleanup() {
    network_name="$1"
    set +e
    # this shuts down all containers first too, handy!
    podman network rm -f -t 0 "$network_name"
    set -e
}

run_test() {
    dir="$1"
    shift
    network_name="$1"
    (
    set +exo pipefail
    num="$(echo "$dir" | grep -o '^[0-9]*' | sed 's/^0//')"

    # create the network
    podman network create --disable-dns --internal --subnet $ipv4.$num.0/24 "$network_name"
    #podman network create --disable-dns --internal --ipv6 --subnet 2001:db8::/64 xmpp-proxy-net6

    cp -a ./ "/tmp/xp-logs/$dir/"
    cd "/tmp/xp-logs/$dir/"
    sed -i "s/192\.5\.0\./$ipv4.$num./g" *

    # start the dns server
    run_container "$network_name" $num -d -v ./example.org.zone:/var/named/example.org.zone:ro 10 dns named -g -u named -d 99

    # start the prosody servers if required
    [ -f ./prosody1.cfg.lua ] && run_container "$network_name" $num -d -v ./prosody1.cfg.lua:/etc/prosody/prosody.cfg.lua:ro 20 server1 prosody && podman exec $num-server1 prosodyctl register romeo  one.example.org pass && podman exec $num-server1 prosodyctl register juliet two.example.org pass
    [ -f ./prosody2.cfg.lua ] && run_container "$network_name" $num -d -v ./prosody2.cfg.lua:/etc/prosody/prosody.cfg.lua:ro 30 server2 prosody && podman exec $num-server2 prosodyctl register juliet two.example.org pass
    # or the ejabberd servers todo: ejabberd register fails if server isn't started first, do something to avoid this hacky sleep
    [ -f ./ejabberd1.yml ] && run_container "$network_name" $num -d -v ./ejabberd1.yml:/etc/ejabberd/ejabberd.yml:ro 20 server1 /usr/bin/ejabberdctl foreground && sleep 0.8 && podman exec $num-server1 ejabberdctl register romeo  one.example.org pass && podman exec $num-server1 ejabberdctl register juliet two.example.org pass
    [ -f ./ejabberd2.yml ] && run_container "$network_name" $num -d -v ./ejabberd2.yml:/etc/ejabberd/ejabberd.yml:ro 30 server2 /usr/bin/ejabberdctl foreground && sleep 0.8 && podman exec $num-server2 ejabberdctl register juliet two.example.org pass

    [ -f ./xmpp-proxy1.toml ] && run_container "$network_name" $num -d $xmpp_proxy_bind -v ./xmpp-proxy1.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 40 xp1 xmpp-proxy
    [ -f ./xmpp-proxy2.toml ] && run_container "$network_name" $num -d $xmpp_proxy_bind -v ./xmpp-proxy2.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 50 xp2 xmpp-proxy
    [ -f ./xmpp-proxy3.toml ] && run_container "$network_name" $num -d $xmpp_proxy_bind -v ./xmpp-proxy3.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 60 xp3 xmpp-proxy
    [ -f ./nginx1.conf ] && run_container "$network_name" $num -d -v ./nginx1.conf:/etc/nginx/nginx.conf:ro 70 web1 nginx
    [ -f ./nginx2.conf ] && run_container "$network_name" $num -d -v ./nginx2.conf:/etc/nginx/nginx.conf:ro 80 web2 nginx

    # run the actual tests
    tests="$(cat tests || echo "-d .")"
    run_container "$network_name" $num -w /scansion/ 89 scansion scansion $tests
    # juliet_messages_romeo.scs  juliet_presence.scs  romeo_messages_juliet.scs  romeo_presence.scs
    )
}

try_run() {
      export dir="$(echo "$1" | tr -d '/')"

      set +exo pipefail
      echo "$dir" | grep -E "$dir_pattern" &>/dev/null
      [ $? -ne 0 ] && echo "$dir" >> "$skipped" && return
      set -e

      cd "$dir"

      [ $run_blocked -eq 0 ] && [ -e blocked ] && echo "$dir" >> "$skipped" && cd .. && return

      set +e
      network_name="xmpp-proxy-$dir"
      run_test "$dir" "$network_name"
      if [ $? -eq 0 ]
      then
          echo "$dir" >> "$success"
      else
          echo "$dir" >> "$error"
      fi
      # this usually takes a few seconds, but we don't care, background it and ignore output
      cleanup "$network_name" >/dev/null &
      set -e

      cd ..
}

(
set -euxo pipefail

export -f cleanup
podman network ls | grep -o 'xmpp-proxy-[^ ]*' | xargs -n1 --no-run-if-empty cleanup || true

podman image exists "$img" || rebuild_image=1
[ $rebuild_image -eq 0 ] || podman build -f Dockerfile --build-arg="ECDSA=$ecdsa" --build-arg="BUILD=$build" -t "$img" ..
#podman run --rm "$img" openssl pkey -in /etc/prosody/certs/one.example.org.key -text

if [ $build -eq 1 ]
then
    cd ..
    cargo build $build_args
    cd integration
fi

dir_pattern="$(echo "$@" | tr -d '/' | sed -r 's/ +/|/g')"
[ -z "$dir_pattern" ] && dir_pattern='.'

echo -n | tee "$success" "$error" "$skipped"

# all variables the functions use
export dir_pattern ipv4 build build_args img xmpp_proxy_bind run_blocked rebuild_image ecdsa success error skipped
# all the functions
export -f try_run run_test run_container

set +e
printf '%s\0' */ | xargs -0 --max-procs=$threads -n1 bash -c 'try_run "$@"' _

set +x
cat <<EOF

skipped:    $(sort "$skipped" | tr '\n' ' ')

successful: $(sort "$success" | tr '\n' ' ')

failed:     $(sort "$error" | tr '\n' ' ')
EOF

exit $(tr ' ' '\n' < "$error" | wc -l)
)

