/* Extra Wi-Fi networks (SSID2..SSID4 on ra1..ra3). A network whose
 * SYS_NETn_IP holds an address/prefix (e.g. 10.0.2.1/24) is routed: it stays
 * out of the LAN bridge, gets that address, its own DHCP pool and NAT to the
 * WAN. An empty SYS_NETn_IP keeps it bridged with the LAN, as before. */
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#include <cfg_net.h>
#include <cfg_dns.h>
#include "net_extra.h"

extern int CFG_get_str(int id, char *val);
extern cyg_bool_t netif_alias_cfg(const char *intf, struct ip_set *setp);
extern int DHCPS_net_start(const char *ifname, unsigned long ip, unsigned long mask, unsigned long dns);

static const int ip_ids[NET_EXTRA_MAX] = { CFG_SYS_NET2_IP, CFG_SYS_NET3_IP, CFG_SYS_NET4_IP };

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
		/* clients use the upstream DNS server (reachable through NAT) */
		DHCPS_net_start(names[i], ip, mask, DNS_group_get(0));
	}
}
