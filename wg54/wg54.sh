#!/bin/sh
# Starts wg54 on DD-WRT micro (Linux 2.4, BCM5354) from nvram settings:
#   wg54_peer   server public key (base64)
#   wg54_ep     server IP address          wg54_port  server UDP port (51820)
#   wg54_addr   tunnel address/prefix, e.g. 10.0.0.2/24
#   wg54_ka     keepalive seconds (25)     wg54_ntp   NTP server IP (optional)
#   wg54_key    private key; created here (and committed) when empty
# The binary is expected at /tmp/wg54 (RAM); run again to restart.
#   sh /tmp/wg54.sh            start / restart
#   sh /tmp/wg54.sh stop
#   sh /tmp/wg54.sh fw         re-add the iptables rules (from rc_firewall)
#   sh /tmp/wg54.sh watch      start, then restart whenever it dies (not after stop)
W=/tmp/wg54
IF=wg0

rule() { iptables -D "$@" 2>/dev/null; iptables -I "$@"; }
unrule() { iptables -D "$@" 2>/dev/null; }
rules() {
	# the encapsulated copy of every outgoing packet must not come back in
	rule INPUT -p 4 -s 127.0.0.1 -d 127.0.0.2 -j DROP
	rule INPUT -i $IF -j ACCEPT
	rule FORWARD -i $IF -j ACCEPT
	rule FORWARD -o $IF -j ACCEPT
}
if [ "$1" = fw ]; then
	[ -f /tmp/wg54.pid ] && rules
	exit 0
fi
if [ "$1" = watch ]; then
	sh "$0"
	while sleep 60; do
		[ -f /tmp/wg54.pid ] || exit 0
		[ -d "/proc/$(cat /tmp/wg54.pid)" ] || sh "$0"
	done
fi

if [ -f /tmp/wg54.pid ]; then
	kill "$(cat /tmp/wg54.pid)" 2>/dev/null
	rm -f /tmp/wg54.pid
fi
if [ "$1" = stop ]; then
	ip tunnel del $IF 2>/dev/null
	unrule INPUT -p 4 -s 127.0.0.1 -d 127.0.0.2 -j DROP
	unrule INPUT -i $IF -j ACCEPT
	unrule FORWARD -i $IF -j ACCEPT
	unrule FORWARD -o $IF -j ACCEPT
	exit 0
fi

PEER=$(nvram get wg54_peer)
EP=$(nvram get wg54_ep)
PORT=$(nvram get wg54_port)
ADDR=$(nvram get wg54_addr)
KA=$(nvram get wg54_ka)
NTP=$(nvram get wg54_ntp)
[ -n "$PORT" ] || PORT=51820
[ -n "$KA" ] || KA=25
if [ -z "$PEER" ] || [ -z "$EP" ] || [ -z "$ADDR" ]; then
	echo "wg54.sh: set wg54_peer, wg54_ep and wg54_addr in nvram" >&2
	exit 1
fi
chmod 755 $W

umask 077
KEY=$(nvram get wg54_key)
if [ -z "$KEY" ]; then
	KEY=$($W genkey) || exit 1
	nvram set wg54_key="$KEY"
	nvram commit
fi
echo "$KEY" > /tmp/wg54.key
echo "wg54.sh: public key $($W pubkey /tmp/wg54.key)"

insmod ipip 2>/dev/null
ip tunnel del $IF 2>/dev/null
ip tunnel add $IF mode ipip local 127.0.0.1 remote 127.0.0.2 || exit 1
ip addr add "$ADDR" dev $IF
ip link set $IF mtu 1420 up
echo 0 > /proc/sys/net/ipv4/conf/$IF/rp_filter
rules

$W run /tmp/wg54.key "$PEER" "$EP" "$PORT" $IF "$KA" $NTP > /tmp/wg54.log 2>&1 &
echo $! > /tmp/wg54.pid
