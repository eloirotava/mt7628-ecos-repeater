# DD-WRT boot hook for wg54 (micro has no HTTPS, no jffs and no gunzip).
# Micro builds do not run rc_startup, so this goes in rc_firewall, which runs
# at boot and on every firewall rebuild (that flushes the wg54 rules).
# Install once on the router (binary and wg54.sh served over HTTP on the LAN):
#   nvram set wg54_url="http://SERVER:PORT [http://OTHER:PORT]"
#   nvram set rc_firewall="$(cat boot.sh)"
#   nvram commit
if [ -f /tmp/wg54.boot ]; then
	[ -f /tmp/wg54.sh ] && sh /tmp/wg54.sh fw
	exit 0
fi
touch /tmp/wg54.boot
# The micro busybox has no mv, rm or ls.
(
cd /tmp
while :; do
	for u in $(nvram get wg54_url); do
		if wget -q -O wg54 "$u/wg54" && wget -q -O wg54.sh "$u/wg54.sh" &&
			chmod 755 wg54 && ./wg54 selftest; then
			echo "boot: $u at $(cat /proc/uptime)" >> /tmp/wg54.boot
			exec sh /tmp/wg54.sh watch
		fi
	done
	sleep 30
done
) > /dev/null 2>&1 &
