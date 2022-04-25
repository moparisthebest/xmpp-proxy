#!/bin/sh
set -euxo pipefail

ipv4='192.5.0'

# change to this directory
cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

usage() { echo "Usage: $0 [-i 192.5.0] [-d] [-r] [-b] [-n]" 1>&2; exit 1; }

build=0
build_args=''
img='xmpp-proxy-test'
xmpp_proxy_bind=''
run_blocked=0
rebuild_image=0
ecdsa=0
while getopts ":i:drbeno" o; do
    case "${o}" in
        i)
            ipv4=${OPTARG}
            echo "you must change the IP in all the containers for this to work, broken for now, exiting..."
            exit 1
            ;;
        d)
            build=1
            xmpp_proxy_bind='-v ../../target/debug/xmpp-proxy:/usr/bin/xmpp-proxy:ro'
            ;;
        r)
            build=1
            build_args='--release'
            xmpp_proxy_bind='-v ../../target/release/xmpp-proxy:/usr/bin/xmpp-proxy:ro'
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

run_container() {
    set +x
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
    podman run "${args[@]}" --rm --log-driver=k8s-file "--log-opt=path=/tmp/xp-logs/$dir-$name.log" --network xmpp-proxy-net4 --dns-search example.org --dns "$ipv4.10" --hostname "$name" --name "$name" --ip "$ipv4.$ip" "$img" "$@"
}

cleanup() {
    set +e
    podman stop -i -t 0 dns server1 server2 xp1 xp2 xp3 web1 web2 scansion
    podman rm -f dns server1 server2 xp1 xp2 xp3 web1 web2 scansion
    # this shuts down all containers first too, handy!
    podman network rm -f xmpp-proxy-net4
    set -e
}

run_test() {
    (
    set -e
    podman network exists xmpp-proxy-net4 && cleanup
    # create the network
    podman network create --disable-dns --internal --subnet $ipv4.0/24 xmpp-proxy-net4
    #podman network create --disable-dns --internal --ipv6 --subnet 2001:db8::/64 xmpp-proxy-net6

    # start the dns server
    run_container -d -v ./example.org.zone:/var/named/example.org.zone:ro 10 dns named -g -u named -d 99

    # start the prosody servers if required
    [ -f ./prosody1.cfg.lua ] && run_container -d -v ./prosody1.cfg.lua:/etc/prosody/prosody.cfg.lua:ro 20 server1 prosody
    [ -f ./prosody2.cfg.lua ] && run_container -d -v ./prosody2.cfg.lua:/etc/prosody/prosody.cfg.lua:ro 30 server2 prosody
    # or the ejabberd servers
    [ -f ./ejabberd1.yml ] && run_container -d -v ./ejabberd1.yml:/etc/ejabberd/ejabberd.yml:ro 20 server1 /usr/bin/ejabberdctl foreground
    [ -f ./ejabberd2.yml ] && run_container -d -v ./ejabberd2.yml:/etc/ejabberd/ejabberd.yml:ro 30 server2 /usr/bin/ejabberdctl foreground

    [ -f ./xmpp-proxy1.toml ] && run_container -d $xmpp_proxy_bind -v ./xmpp-proxy1.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 40 xp1 xmpp-proxy
    [ -f ./xmpp-proxy2.toml ] && run_container -d $xmpp_proxy_bind -v ./xmpp-proxy2.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 50 xp2 xmpp-proxy
    [ -f ./xmpp-proxy3.toml ] && run_container -d $xmpp_proxy_bind -v ./xmpp-proxy3.toml:/etc/xmpp-proxy/xmpp-proxy.toml:ro 60 xp3 xmpp-proxy
    [ -f ./nginx1.conf ] && run_container -d -v ./nginx1.conf:/etc/nginx/nginx.conf:ro 70 web1 nginx
    [ -f ./nginx2.conf ] && run_container -d -v ./nginx2.conf:/etc/nginx/nginx.conf:ro 80 web2 nginx

    # we don't care if these fail
    set +e
    podman exec server1 prosodyctl register romeo  one.example.org pass
    podman exec server1 prosodyctl register juliet two.example.org pass
    podman exec server2 prosodyctl register romeo  one.example.org pass
    podman exec server2 prosodyctl register juliet two.example.org pass

    podman exec server1 ejabberdctl register romeo  one.example.org pass
    podman exec server1 ejabberdctl register juliet two.example.org pass
    podman exec server2 ejabberdctl register romeo  one.example.org pass
    podman exec server2 ejabberdctl register juliet two.example.org pass
    set -e

    # run the actual tests
    tests="$(cat tests || echo "-d .")"
    run_container -w /scansion/ 89 scansion scansion $tests
    # juliet_messages_romeo.scs  juliet_presence.scs  romeo_messages_juliet.scs  romeo_presence.scs

    cleanup
    )
}

(
set -euxo pipefail

podman network exists xmpp-proxy-net4 && cleanup

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

success=()
error=()
skipped=()

for dir in */
do

    export dir="$(echo "$dir" | tr -d '/')"

    set +e
    echo "$dir" | grep -E "$dir_pattern" &>/dev/null
    [ $? -ne 0 ] && skipped+=("$dir") && continue
    set -e

    cd "$dir"

    [ $run_blocked -eq 0 ] && [ -e blocked ] && skipped+=("$dir") && cd .. && continue

    set +e
    run_test
    if [ $? -eq 0 ]
    then
        success+=("$dir")
    else
        error+=("$dir")
        cleanup
    fi
    set -e

    cd ..

done

set +x
cat <<EOF

skipped:    ${skipped[@]}

successful: ${success[@]}

failed:     ${error[@]}
EOF

exit ${#error[@]}
)

