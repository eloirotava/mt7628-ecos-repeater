# DD-WRT boot hook for wg54 (micro has no HTTPS, no jffs and no gunzip).
# Install once on the router (binary and wg54.sh served over HTTP on the LAN):
#   nvram set wg54_url="http://SERVER:PORT [http://OTHER:PORT]"
#   nvram set rc_startup="$(cat boot.sh)"
#   nvram set rc_firewall='[ -f /tmp/wg54.sh ] && sh /tmp/wg54.sh fw'
#   nvram commit
(
cd /tmp
while :; do
	for u in $(nvram get wg54_url); do
		if wget -q -O wg54.new "$u/wg54" && wget -q -O wg54.sh.new "$u/wg54.sh" &&
			chmod 755 wg54.new && ./wg54.new selftest; then
			mv wg54.new wg54
			mv wg54.sh.new wg54.sh
			exec sh /tmp/wg54.sh watch
		fi
		rm -f wg54.new wg54.sh.new
	done
	sleep 30
done
) > /dev/null 2>&1 &
