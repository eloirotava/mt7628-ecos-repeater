/* Extra Wi-Fi networks (SSID2..SSID7 on ra1..ra6). A network whose
 * SYS_NETn_IP holds an address/prefix (e.g. 10.0.2.1/24) is routed: it stays
 * out of the LAN bridge, gets that address, its own DHCP pool and NAT to the
 * WAN. An empty SYS_NETn_IP keeps it bridged with the LAN, as before. */
#ifndef NET_EXTRA_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <net/if.h>
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
extern int DHCPS_net_add_port(const char *ifname, const char *port);
extern void FW_setrule(char *cmdbuf);

static const int ip_ids[NET_EXTRA_MAX] = { CFG_SYS_NET1_IP, CFG_SYS_NET2_IP, CFG_SYS_NET3_IP, CFG_SYS_NET4_IP, CFG_SYS_NET5_IP, CFG_SYS_NET6_IP, CFG_SYS_NET7_IP };
static const int reach_ids[NET_EXTRA_MAX] = { CFG_SYS_NET1_REACH, CFG_SYS_NET2_REACH, CFG_SYS_NET3_REACH, CFG_SYS_NET4_REACH, CFG_SYS_NET5_REACH, CFG_SYS_NET6_REACH, CFG_SYS_NET7_REACH };
static const int internet_ids[NET_EXTRA_MAX] = { CFG_SYS_NET1_INTERNET, CFG_SYS_NET2_INTERNET, CFG_SYS_NET3_INTERNET, CFG_SYS_NET4_INTERNET, CFG_SYS_NET5_INTERNET, CFG_SYS_NET6_INTERNET, CFG_SYS_NET7_INTERNET };
static const int via_ids[NET_EXTRA_MAX] = { CFG_SYS_NET1_VIA, CFG_SYS_NET2_VIA, CFG_SYS_NET3_VIA, CFG_SYS_NET4_VIA, CFG_SYS_NET5_VIA, CFG_SYS_NET6_VIA, CFG_SYS_NET7_VIA };

/* Network n (1..7) sends its Internet traffic through wg0. */
int net_extra_via_wg(int n)
{
	char val[16];
	if (n < 1 || n > NET_EXTRA_MAX) return 0;
	val[0] = 0;
	CFG_get_str(via_ids[n - 1], val);
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

/* Bridge-based setup (opmode 3): the device is a node of the upstream
 * network; routed networks are translated to its address there. */
int net_extra_bridge_base(void)
{
	char val[8];
	val[0] = 0;
	CFG_get_str(CFG_SYS_OPMODE, val);
	return atoi(val) == 3;
}

/* Network (2..7) the Ethernet port belongs to, 0 if none: only with a
 * Wi-Fi uplink (opmode 2 or 3: the port is free) and a routed network that
 * is active. The port and raN then form a bridge cluster of their own. */
int net_extra_eth_net(void)
{
	char val[8];
	int n, op, apcli, bss;
	val[0] = 0;
	CFG_get_str(CFG_SYS_ETH_NET, val);
	n = atoi(val);
	if (n < 2 || n > NET_EXTRA_MAX) return 0;
	val[0] = 0; CFG_get_str(CFG_SYS_OPMODE, val); op = atoi(val);
	val[0] = 0; CFG_get_str(CFG_WLN_ApCliEnable, val); apcli = atoi(val);
	val[0] = 0; CFG_get_str(CFG_WLN_BssidNum, val); bss = atoi(val);
	if ((op != 2 && op != 3) || !apcli || n > bss) return 0;
	return net_extra_routed(n, 0, 0) ? n : 0;
}

/* Network n (1..7) routed? Fills ip/mask when given. Network 1 is routed
 * here only in bridge-based setups; otherwise it is the LAN. */
int net_extra_routed(int n, unsigned long *ip, unsigned long *mask)
{
	char val[64];
	unsigned long i, m;
	if (n < 1 || n > NET_EXTRA_MAX) return 0;
	if (n == 1 && !net_extra_bridge_base()) return 0;
	val[0] = 0;
	CFG_get_str(ip_ids[n - 1], val);
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
	for (n = 1; n <= bss && n <= NET_EXTRA_MAX && count < max; n++)
		if (net_extra_routed(n, 0, 0)) {
			strcpy(names[count], "ra0");
			names[count][2] = (char)('0' + n - 1);
			count++;
		}
	return count;
}

/* After the Wi-Fi interfaces are up: address and DHCP for routed networks. */
#ifndef NET_EXTRA_HOST_TEST
/* Policy routing: Internet-bound packets from a network sent through the
 * tunnel leave by the route to the WireGuard server instead of the default
 * route (route-to is compiled out of this IPFilter). */
extern u_long (*ip_policy_nexthop)(struct mbuf *);
extern struct ifnet *ifunit(const char *name);
static struct ifnet *wg_src_ifp[NET_EXTRA_MAX], *wg_src_eth;
static u_long wg_nexthop;

static u_long policy_nexthop(struct mbuf *m)
{
	int i;
	for (i = 0; i < NET_EXTRA_MAX; i++)
		if (wg_src_ifp[i] && m->m_pkthdr.rcvif == wg_src_ifp[i])
			return wg_nexthop;
	if (wg_src_eth && m->m_pkthdr.rcvif == wg_src_eth)
		return wg_nexthop;
	return 0;
}

static void policy_setup(char names[][8], int count)
{
	char val[64];
	unsigned long ip, mask, nh;
	int i, any = 0;
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_ADDR, val);
	if (net_extra_parse(val, &ip, &mask)) return;
	/* the server: first host of the tunnel subnet, or the second if that is us */
	nh = (ip & mask) | htonl(1);
	if (nh == ip) nh = (ip & mask) | htonl(2);
	for (i = 0; i < count && i < NET_EXTRA_MAX; i++)
		if (net_extra_via_wg(names[i][2] - '0' + 1) && (wg_src_ifp[i] = ifunit(names[i])))
			any = 1;
	/* the Ethernet port of a network sent through the tunnel */
	{
		int e = net_extra_eth_net();
		wg_src_eth = e && net_extra_via_wg(e) ? ifunit(NET_EXTRA_ETH) : 0;
		if (wg_src_eth) any = 1;
	}
	wg_nexthop = nh;
	if (any) ip_policy_nexthop = policy_nexthop;
}
#endif

#ifndef NET_EXTRA_HOST_TEST
extern void NAT_setrule(char *cmd);
/* Bridge-based setup: routed networks are translated to the device's
 * address on the bridge (upstream network), or to wg0 when sent through
 * the tunnel. NAT_init returns early without a WAN, so nothing flushes
 * these rules later. */
static void nat_to_bridge(char names[][8], int count)
{
	char cmd[160];
	int i;
	int e = net_extra_eth_net();
	for (i = 0; i < count + (e ? 1 : 0); i++) {
		/* the extra round is the Ethernet port of network e */
		int k = i < count ? i : -1;
		const char *from = k >= 0 ? names[k] : NET_EXTRA_ETH;
		int num = k >= 0 ? names[k][2] - '0' + 1 : e;
		const char *out = net_extra_via_wg(num) && ifunit("wg0") ? "wg0" : SYS_lan_if;
		/* rules differing only in fromif count as duplicates: own ranges per source */
		int plo = 10000 + i * 3500, ilo = 45000 + i * 1400;
		snprintf(cmd, sizeof cmd, "map %s fromif %s 0/0 -> 0/32 portmap tcp/udp %d:%d\n", out, from, plo, plo + 3499);
		NAT_setrule(cmd);
		snprintf(cmd, sizeof cmd, "map %s fromif %s 0/0 -> 0/32 icmpidmap icmp %d:%d\n", out, from, ilo, ilo + 1399);
		NAT_setrule(cmd);
		if (strcmp(out, SYS_lan_if)) {
			/* local traffic to the upstream network still leaves by the bridge */
			snprintf(cmd, sizeof cmd, "map %s fromif %s 0/0 -> 0/32 portmap tcp/udp %d:%d\n", SYS_lan_if, from, plo, plo + 3499);
			NAT_setrule(cmd);
		}
	}
}
#endif

/* DNS for networks sent through the tunnel */
static unsigned long wg_dns(void)
{
	char val[20];
	unsigned long a;
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_DNS, val);
	a = inet_addr(val);
	return val[0] && a != 0xffffffffUL && a ? a : inet_addr("1.1.1.1");
}

void net_extra_apply(void)
{
#ifndef NET_EXTRA_HOST_TEST
	{
		/* frames from the port keep it as their receiving interface (if_ethersubr.c) */
		extern struct ifnet *net_extra_port;
		net_extra_port = net_extra_eth_net() ? ifunit(NET_EXTRA_ETH) : 0;
	}
#endif
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
		 * NAT); through the tunnel the home router's DNS is not reachable, so
		 * those networks get SYS_WG_DNS (default 1.1.1.1) */
		DHCPS_net_start(names[i], ip, mask, net_extra_via_wg(names[i][2] - '0' + 1) ? wg_dns() : 0);
		if (net_extra_eth_net() == names[i][2] - '0' + 1)
			DHCPS_net_add_port(names[i], NET_EXTRA_ETH);
	}
	/* Wi-Fi is up: isolation rules may be loaded now (no-op if the
	 * firewall already has them); later firewall reloads add them again. */
#ifndef NET_EXTRA_HOST_TEST
	policy_setup(names, count);
	if (count && net_extra_bridge_base()) nat_to_bridge(names, count);
#endif
	net_extra_fw_ready();
	if (count) net_extra_fw_rules(FW_setrule);
}

/* Isolation rules are loaded once per firewall generation and only after the
 * Wi-Fi interfaces are up: running this from the monitor thread while the
 * driver initialises shifted the boot timing enough to expose a driver race
 * (TX before the BSS is ready -> crash in ParseTxSPacket). */
static volatile int wifi_ready, fw_applied;
void net_extra_fw_ready(void) { wifi_ready = 1; }

#ifndef NET_EXTRA_HOST_TEST
/* The LAN address is part of the isolation rules; in bridge-based setups it
 * is a DHCP lease that arrives after the rules were loaded: rebuild them. */
void net_extra_lan_changed(void)
{
	extern void FW_flush(void);
	extern void FW_init(void);
	char names[NET_EXTRA_MAX][8];
	if (!wifi_ready || !net_extra_ifnames(names, NET_EXTRA_MAX)) return;
	diag_printf("net: LAN address changed, reloading isolation rules\n");
	FW_flush();
	FW_init();
}
#endif
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
	/* an address not known yet (bridge-based LAN before its DHCP lease)
	 * would turn into "to any" and block everything */
	if (len == 0) return;
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
		CFG_get_str(reach_ids[num[i] - 1], reach[i]);
		val[0] = 0;
		CFG_get_str(internet_ids[num[i] - 1], val);
		internet[i] = strcmp(val, "0") != 0;
		via_wg[i] = net_extra_via_wg(num[i]);
	}
	/* "net1" names the LAN when network 1 is the main LAN (not routed here) */
	for (i = 0; i < count; i++)
		if (!net_extra_routed(1, 0, 0) && has(reach[i], "net1") && !has(reach[i], "lan") && strlen(reach[i]) + 5 < sizeof reach[i])
			strcat(reach[i], reach[i][0] ? ",lan" : "lan");
	if (count) diag_printf("net: isolation rules for %d routed network(s)\n", count);
	{
		/* the Ethernet port in a routed network gets that network's rules */
		int e = net_extra_eth_net();
		for (i = 0; i < count && count < NET_EXTRA_MAX; i++)
			if (num[i] == e) {
				strcpy(names[count], NET_EXTRA_ETH);
				num[count] = num[i]; ip[count] = ip[i]; mask[count] = mask[i];
				strcpy(reach[count], reach[i]); internet[count] = internet[i]; via_wg[count] = via_wg[i];
				count++;
				break;
			}
	}
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
				if (num[j] != num[i]) rule(set, "block in quick on %s from any to %s/%d\n", x, ip[j], 32);
		}
		if (!has(reach[i], "lan"))
			rule(set, "block in quick on %s from any to %s/%d\n", x, SYS_lan_ip & SYS_lan_mask, prefix(SYS_lan_mask));
		for (j = 0; j < count; j++) {
			char key[8];
			snprintf(key, sizeof key, "net%d", num[j]);
			if (num[j] != num[i] && !has(reach[i], key))
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
				if (num[j] != num[i] && has(reach[i], key))
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
				if (num[j] != num[i] && has(reach[i], key))
					rule(set, "pass in quick on %s from any to %s/%d\n", x, ip[j] & mask[j], prefix(mask[j]));
			}
			snprintf(buf, sizeof buf, "block in quick on %s all\n", x);
			set(buf);
		}
	}
}
