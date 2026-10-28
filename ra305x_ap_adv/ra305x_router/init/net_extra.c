/* Extra Wi-Fi networks (SSID2..SSID4 on ra1..ra3). A network whose
 * SYS_NETn_IP holds an address/prefix (e.g. 10.0.2.1/24) is routed: it stays
 * out of the LAN bridge, gets that address, its own DHCP pool and NAT to the
 * WAN. An empty SYS_NETn_IP keeps it bridged with the LAN, as before. */
#ifndef NET_EXTRA_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#include <cfg_net.h>
#include <cfg_dns.h>
#include <sys_status.h>
#endif
#include "net_extra.h"

extern int CFG_get_str(int id, char *val);
extern cyg_bool_t netif_alias_cfg(const char *intf, struct ip_set *setp);
extern int DHCPS_net_start(const char *ifname, unsigned long ip, unsigned long mask, unsigned long dns);
extern void FW_setrule(char *cmdbuf);

static const int ip_ids[NET_EXTRA_MAX] = { CFG_SYS_NET2_IP, CFG_SYS_NET3_IP, CFG_SYS_NET4_IP };
static const int reach_ids[NET_EXTRA_MAX] = { CFG_SYS_NET2_REACH, CFG_SYS_NET3_REACH, CFG_SYS_NET4_REACH };
static const int internet_ids[NET_EXTRA_MAX] = { CFG_SYS_NET2_INTERNET, CFG_SYS_NET3_INTERNET, CFG_SYS_NET4_INTERNET };
static const int via_ids[NET_EXTRA_MAX] = { CFG_SYS_NET2_VIA, CFG_SYS_NET3_VIA, CFG_SYS_NET4_VIA };

/* Network n (2..4) sends its Internet traffic through wg0. */
int net_extra_via_wg(int n)
{
	char val[16];
	if (n < 2 || n > 1 + NET_EXTRA_MAX) return 0;
	val[0] = 0;
	CFG_get_str(via_ids[n - 2], val);
	return !strcmp(val, "wg");
}

/* "a.b.c.d/n" -> address and mask (network order); 0 if valid */
int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask)
{
	char a[20];
	const char *slash = strchr(s, '/');
	struct in_addr in;
	int bits;
	if (!slash || slash - s >= (int)sizeof a) return -1;
	memcpy(a, s, slash - s);
	a[slash - s] = 0;
	bits = atoi(slash + 1);
	if (bits < 8 || bits > 30 || !inet_aton(a, &in)) return -1;
	*ip = in.s_addr;
	*mask = htonl(~(0xffffffffUL >> bits));
	if (((*ip) & ~(*mask)) == 0 || ((*ip) | (*mask)) == 0xffffffffUL) return -1; /* network or broadcast */
	return 0;
}

/* Network n (2..4) routed? Fills ip/mask when given. */
int net_extra_routed(int n, unsigned long *ip, unsigned long *mask)
{
	char val[64];
	unsigned long i, m;
	if (n < 2 || n > 1 + NET_EXTRA_MAX) return 0;
	val[0] = 0;
	CFG_get_str(ip_ids[n - 2], val);
	if (!val[0] || net_extra_parse(val, &i, &m)) return 0;
	if (ip) *ip = i;
	if (mask) *mask = m;
	return 1;
}

/* Interface names of the routed networks among the active SSIDs. */
int net_extra_ifnames(char names[][8], int max)
{
	char val[16];
	int bss, n, count = 0;
	val[0] = 0;
	CFG_get_str(CFG_WLN_BssidNum, val);
	bss = atoi(val);
	for (n = 2; n <= bss && n <= 1 + NET_EXTRA_MAX && count < max; n++)
		if (net_extra_routed(n, 0, 0)) {
			strcpy(names[count], "ra0");
			names[count][2] = (char)('0' + n - 1);
			count++;
		}
	return count;
}

/* After the Wi-Fi interfaces are up: address and DHCP for routed networks. */
void net_extra_apply(void)
{
	char names[NET_EXTRA_MAX][8];
	int i, count = net_extra_ifnames(names, NET_EXTRA_MAX);
	for (i = 0; i < count; i++) {
		struct ip_set set;
		unsigned long ip, mask;
		net_extra_routed(names[i][2] - '0' + 1, &ip, &mask);
		memset(&set, 0, sizeof set);
		set.ip = ip;
		set.netmask = mask;
		if (!netif_alias_cfg(names[i], &set)) diag_printf("net: %s address failed\n", names[i]);
		/* dns 0: offer the upstream DNS current at each reply (reachable through
		 * NAT); through the tunnel the home router's DNS is not reachable */
		DHCPS_net_start(names[i], ip, mask, net_extra_via_wg(names[i][2] - '0' + 1) ? inet_addr("1.1.1.1") : 0);
	}
	/* Wi-Fi is up: isolation rules may be loaded now (no-op if the
	 * firewall already has them); later firewall reloads add them again. */
	net_extra_fw_ready();
	if (count) net_extra_fw_rules(FW_setrule);
}

/* Isolation rules are loaded once per firewall generation and only after the
 * Wi-Fi interfaces are up: running this from the monitor thread while the
 * driver initialises shifted the boot timing enough to expose a driver race
 * (TX before the BSS is ready -> crash in ParseTxSPacket). */
static volatile int wifi_ready, fw_applied;
void net_extra_fw_ready(void) { wifi_ready = 1; }
void net_extra_fw_flushed(void) { fw_applied = 0; }

/* comma list membership, e.g. has("lan,wg", "wg") */
static int has(const char *list, const char *item)
{
	size_t n = strlen(item);
	const char *p = list;
	while ((p = strstr(p, item))) {
		if ((p == list || p[-1] == ',') && (p[n] == 0 || p[n] == ',')) return 1;
		p += n;
	}
	return 0;
}

static int prefix(unsigned long mask)
{
	unsigned long m = ntohl(mask);
	int n = 0;
	while (m & 0x80000000UL) { n++; m <<= 1; }
	return n;
}

static void rule(void (*set)(char *), const char *fmt, const char *ifn, unsigned long ip, int len)
{
	char buf[160], a[16];
	strcpy(a, inet_ntoa(*(struct in_addr *)&ip));
	snprintf(buf, sizeof buf, fmt, ifn, a, len);
	set(buf);
}

/* IPFilter rules for routed networks (called from FW_basic_rule):
 * others (the LAN, the device) may open connections into a routed network
 * and get replies through state; a routed network reaches only what its
 * REACH list names, plus the Internet unless INTERNET is 0. */
void net_extra_fw_rules(void (*set)(char *))
{
	char names[NET_EXTRA_MAX][8], reach[NET_EXTRA_MAX][64], val[64], buf[160];
	unsigned long ip[NET_EXTRA_MAX], mask[NET_EXTRA_MAX], wg_ip = 0, wg_mask = 0;
	int internet[NET_EXTRA_MAX], num[NET_EXTRA_MAX], via_wg[NET_EXTRA_MAX];
	int i, j, count;
	const unsigned long rescue = inet_addr("192.168.11.1");

	if (!wifi_ready || fw_applied) return;
	fw_applied = 1;
	count = net_extra_ifnames(names, NET_EXTRA_MAX);

	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_ADDR, val);
	if (val[0]) net_extra_parse(val, &wg_ip, &wg_mask);
	for (i = 0; i < count; i++) {
		num[i] = names[i][2] - '0' + 1;
		net_extra_routed(num[i], &ip[i], &mask[i]);
		reach[i][0] = 0;
		CFG_get_str(reach_ids[num[i] - 2], reach[i]);
		val[0] = 0;
		CFG_get_str(internet_ids[num[i] - 2], val);
		internet[i] = strcmp(val, "0") != 0;
		via_wg[i] = net_extra_via_wg(num[i]);
	}
	if (count) diag_printf("net: isolation rules for %d routed network(s)\n", count);
	for (i = 0; i < count; i++) {
		const char *x = names[i];
		snprintf(buf, sizeof buf, "pass out quick on %s from any to any keep state\n", x);
		set(buf);
		if (!has(reach[i], "device")) {
			rule(set, "block in quick on %s from any to %s/%d\n", x, ip[i], 32);
			rule(set, "block in quick on %s from any to %s/%d\n", x, SYS_lan_ip, 32);
			rule(set, "block in quick on %s from any to %s/%d\n", x, rescue, 32);
			if (wg_ip) rule(set, "block in quick on %s from any to %s/%d\n", x, wg_ip, 32);
			for (j = 0; j < count; j++)
				if (j != i) rule(set, "block in quick on %s from any to %s/%d\n", x, ip[j], 32);
		}
		if (!has(reach[i], "lan"))
			rule(set, "block in quick on %s from any to %s/%d\n", x, SYS_lan_ip & SYS_lan_mask, prefix(SYS_lan_mask));
		for (j = 0; j < count; j++) {
			char key[8];
			snprintf(key, sizeof key, "net%d", num[j]);
			if (j != i && !has(reach[i], key))
				rule(set, "block in quick on %s from any to %s/%d\n", x, ip[j] & mask[j], prefix(mask[j]));
		}
		if (wg_ip && !has(reach[i], "wg"))
			rule(set, "block in quick on %s from any to %s/%d\n", x, wg_ip & wg_mask, prefix(wg_mask));
		if (internet[i] && via_wg[i]) {
			/* allowed local destinations stay local; everything else is
			 * routed into the WireGuard tunnel (NAT to the wg0 address) */
			if (has(reach[i], "device")) rule(set, "pass in quick on %s from any to %s/%d\n", x, ip[i], 32);
			if (has(reach[i], "lan")) rule(set, "pass in quick on %s from any to %s/%d\n", x, SYS_lan_ip & SYS_lan_mask, prefix(SYS_lan_mask));
			for (j = 0; j < count; j++) {
				char key[8];
				snprintf(key, sizeof key, "net%d", num[j]);
				if (j != i && has(reach[i], key))
					rule(set, "pass in quick on %s from any to %s/%d\n", x, ip[j] & mask[j], prefix(mask[j]));
			}
			snprintf(buf, sizeof buf, "pass in quick on %s to wg0 from any to any\n", x);
			set(buf);
		}
		if (!internet[i]) {
			/* only the allowed local destinations, nothing beyond */
			if (has(reach[i], "device")) rule(set, "pass in quick on %s from any to %s/%d\n", x, ip[i], 32);
			if (has(reach[i], "lan")) rule(set, "pass in quick on %s from any to %s/%d\n", x, SYS_lan_ip & SYS_lan_mask, prefix(SYS_lan_mask));
			if (wg_ip && has(reach[i], "wg")) rule(set, "pass in quick on %s from any to %s/%d\n", x, wg_ip & wg_mask, prefix(wg_mask));
			for (j = 0; j < count; j++) {
				char key[8];
				snprintf(key, sizeof key, "net%d", num[j]);
				if (j != i && has(reach[i], key))
					rule(set, "pass in quick on %s from any to %s/%d\n", x, ip[j] & mask[j], prefix(mask[j]));
			}
			snprintf(buf, sizeof buf, "block in quick on %s all\n", x);
			set(buf);
		}
	}
}
