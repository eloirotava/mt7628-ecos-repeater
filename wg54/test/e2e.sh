#!/bin/sh
# End to end, as root: wg54 (through qemu-user) <-> kernel WireGuard in a
# network namespace, with the same IPIP device and firewall rule wg54.sh uses.
#   e2e.sh "qemu-mipsel -cpu 4KEcR1" build/wg54
set -eu
Q=$1
B=$2
T=$(mktemp -d)
cleanup() {
	[ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true
	ip netns del wgpeer 2>/dev/null || true
	ip link del v0 2>/dev/null || true
	ip link del wg54t 2>/dev/null || true
	iptables -D INPUT -p 4 -s 127.0.0.1 -d 127.0.0.2 -j DROP 2>/dev/null || true
}
trap cleanup EXIT

modprobe ipip
modprobe wireguard

ip netns add wgpeer
ip link add v0 type veth peer name v1
ip link set v1 netns wgpeer
ip addr add 10.200.0.1/24 dev v0
ip link set v0 up
ip -n wgpeer addr add 10.200.0.2/24 dev v1
ip -n wgpeer link set v1 up
ip -n wgpeer link set lo up

$Q "$B" genkey > "$T/our.key"
OURPUB=$($Q "$B" pubkey "$T/our.key")
wg genkey > "$T/peer.key"
PEERPUB=$(wg pubkey < "$T/peer.key")
echo "our public key: $OURPUB"

ip -n wgpeer link add wgp type wireguard
ip netns exec wgpeer wg set wgp listen-port 51820 private-key "$T/peer.key" \
	peer "$OURPUB" allowed-ips 10.77.0.2/32
ip -n wgpeer addr add 10.77.0.1/24 dev wgp
ip -n wgpeer link set wgp up

ip tunnel add wg54t mode ipip local 127.0.0.1 remote 127.0.0.2
ip addr add 10.77.0.2/24 dev wg54t
ip link set wg54t mtu 1420 up
iptables -I INPUT -p 4 -s 127.0.0.1 -d 127.0.0.2 -j DROP

$Q "$B" run "$T/our.key" "$PEERPUB" 10.200.0.2 51820 wg54t 25 > "$T/wg54.log" 2>&1 &
PID=$!

ok=0
for i in 1 2 3 4 5 6 7 8 9 10; do
	if ping -c1 -W1 10.77.0.1 > /dev/null 2>&1; then ok=1; break; fi
done
cat "$T/wg54.log"
ip netns exec wgpeer wg show wgp
[ $ok = 1 ] || { echo "FAIL: no handshake/ping"; exit 1; }

ping -c5 -i0.2 -W2 10.77.0.1
ping -c3 -W2 -s 1372 -M do 10.77.0.1                     # full 1420 MTU, no fragments
ip netns exec wgpeer ping -c3 -W2 10.77.0.2              # initiated from the peer side
if command -v iperf3 > /dev/null; then
	ip netns exec wgpeer iperf3 -s -D -1
	sleep 1
	iperf3 -c 10.77.0.1 -t 5 | tail -4
fi
kill -0 "$PID" || { echo "FAIL: wg54 died"; exit 1; }
echo "PASS"
