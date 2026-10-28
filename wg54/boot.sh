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
(
# DD-WRT signals the rc_firewall process group once it is done; survive that.
for s in HUP INT TERM; do
	trap "echo boot: $s at \$(cat /proc/uptime) >> /tmp/wg54.boot" $s
done
cd /tmp
while :; do
	for u in $(nvram get wg54_url); do
		if wget -q -O wg54.new "$u/wg54" && wget -q -O wg54.sh.new "$u/wg54.sh" &&
			chmod 755 wg54.new && ./wg54.new selftest; then
			mv wg54.new wg54
			mv wg54.sh.new wg54.sh
			echo "boot: $u at $(cat /proc/uptime)" >> /tmp/wg54.boot
			sh /tmp/wg54.sh watch
			exit 0
		fi
		rm -f wg54.new wg54.sh.new
	done
	sleep 30
done
) > /dev/null 2>&1 &
