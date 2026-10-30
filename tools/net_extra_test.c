/* Host test for init/net_extra.c: routed-network detection and the IPFilter
 * isolation rules. Built by tools/test_wifi_ui.py with -DNET_EXTRA_HOST_TEST. */
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define diag_printf printf

enum { CFG_SYS_NET2_IP = 1, CFG_SYS_NET3_IP, CFG_SYS_NET4_IP, CFG_SYS_NET2_REACH, CFG_SYS_NET3_REACH, CFG_SYS_NET4_REACH,
       CFG_SYS_NET2_INTERNET, CFG_SYS_NET3_INTERNET, CFG_SYS_NET4_INTERNET, CFG_SYS_NET2_VIA, CFG_SYS_NET3_VIA, CFG_SYS_NET4_VIA, CFG_SYS_NET5_IP, CFG_SYS_NET6_IP, CFG_SYS_NET7_IP, CFG_SYS_NET5_REACH, CFG_SYS_NET6_REACH, CFG_SYS_NET7_REACH, CFG_SYS_NET5_INTERNET, CFG_SYS_NET6_INTERNET, CFG_SYS_NET7_INTERNET, CFG_SYS_NET5_VIA, CFG_SYS_NET6_VIA, CFG_SYS_NET7_VIA, CFG_SYS_NET1_IP, CFG_SYS_NET1_REACH, CFG_SYS_NET1_INTERNET, CFG_SYS_NET1_VIA, CFG_SYS_OPMODE, CFG_SYS_WG_DNS, CFG_SYS_ETH_NET, CFG_WLN_ApCliEnable, CFG_WLN_BssidNum, CFG_SYS_WG_ADDR, CFG_MAX };
static char cfg[CFG_MAX][64];
static int CFG_get_str(int id, char *val) { strcpy(val, cfg[id]); return 0; }
struct ip_set { unsigned long ip, netmask; };
static struct ip_set primary_lan_ip_set;
#define SYS_lan_ip   (primary_lan_ip_set.ip)
#define SYS_lan_mask (primary_lan_ip_set.netmask)
typedef int cyg_bool_t;
static cyg_bool_t netif_alias_cfg(const char *intf, struct ip_set *setp) { (void)intf; (void)setp; return 1; }
static int DHCPS_net_start(const char *ifname, unsigned long ip, unsigned long mask, unsigned long dns) { (void)ifname; (void)ip; (void)mask; (void)dns; return 0; }
static int DHCPS_net_add_port(const char *ifname, const char *port) { (void)ifname; (void)port; return 0; }
static unsigned long DNS_group_get(int i) { (void)i; return 0; }
static void FW_setrule(char *r) { (void)r; }
#define extern static /* the file's extern declarations refer to the stubs above */
#include "net_extra.c"
#undef extern

static char rules[64][160];
static int nrules;
static void collect(char *r) { assert(nrules < 64); strcpy(rules[nrules++], r); }
static int find(const char *r) { int i; for (i = 0; i < nrules; i++) if (!strcmp(rules[i], r)) return i; return -1; }

int main(void)
{
	unsigned long ip, mask;
	char names[3][8];
	assert(!net_extra_parse("10.0.2.1/24", &ip, &mask) && ip == inet_addr("10.0.2.1") && mask == inet_addr("255.255.255.0"));
	assert(net_extra_parse("10.0.2.0/24", &ip, &mask) && net_extra_parse("10.0.2.255/24", &ip, &mask));
	assert(net_extra_parse("10.0.2.1", &ip, &mask) && net_extra_parse("10.0.2.1/31", &ip, &mask));

	primary_lan_ip_set.ip = inet_addr("10.0.1.1");
	primary_lan_ip_set.netmask = inet_addr("255.255.255.0");
	strcpy(cfg[CFG_WLN_BssidNum], "3");
	strcpy(cfg[CFG_SYS_NET2_IP], "10.0.2.1/24"); /* IoT: internet only */
	strcpy(cfg[CFG_SYS_NET2_INTERNET], "1");
	strcpy(cfg[CFG_SYS_NET3_IP], "10.0.3.1/24"); /* reaches IoT, no Internet */
	strcpy(cfg[CFG_SYS_NET3_REACH], "net2");
	strcpy(cfg[CFG_SYS_NET3_INTERNET], "0");
	strcpy(cfg[CFG_SYS_NET4_IP], "10.0.4.1/24"); /* inactive: BssidNum 3 */
	strcpy(cfg[CFG_SYS_WG_ADDR], "10.8.0.30/24");
	assert(net_extra_ifnames(names, 3) == 2 && !strcmp(names[0], "ra1") && !strcmp(names[1], "ra2"));

	net_extra_fw_rules(collect);
	assert(nrules == 0); /* not before the Wi-Fi is up */
	net_extra_fw_ready();
	net_extra_fw_rules(collect);
	/* replies to connections others open into each network */
	assert(find("pass out quick on ra1 from any to any keep state\n") >= 0);
	/* IoT reaches neither the device, the LAN, the other network nor WireGuard */
	assert(find("block in quick on ra1 from any to 10.0.2.1/32\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.0.1.1/32\n") >= 0);
	assert(find("block in quick on ra1 from any to 192.168.11.1/32\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.8.0.30/32\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.0.1.0/24\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.0.3.0/24\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.8.0.0/24\n") >= 0);
	assert(find("block in quick on ra1 all\n") < 0); /* Internet allowed */
	/* net3 reaches net2 and nothing else, no Internet */
	assert(find("block in quick on ra2 from any to 10.0.2.0/24\n") < 0);
	assert(find("pass in quick on ra2 from any to 10.0.2.0/24\n") >= 0);
	assert(find("block in quick on ra2 from any to 10.0.1.0/24\n") >= 0);
	assert(find("block in quick on ra2 all\n") > find("pass in quick on ra2 from any to 10.0.2.0/24\n"));
	/* the network 4 settings are ignored while its SSID is off */
	{ int i; for (i = 0; i < nrules; i++) assert(!strstr(rules[i], "ra3") && !strstr(rules[i], "10.0.4.")); }

	/* device access and lan in the list */
	nrules = 0;
	net_extra_fw_rules(collect);
	assert(nrules == 0); /* once per firewall generation */
	net_extra_fw_flushed();
	strcpy(cfg[CFG_SYS_NET2_REACH], "device,lan");
	net_extra_fw_rules(collect);
	assert(find("block in quick on ra1 from any to 10.0.2.1/32\n") < 0);
	assert(find("block in quick on ra1 from any to 10.0.1.0/24\n") < 0);
	assert(find("block in quick on ra1 from any to 10.0.3.0/24\n") >= 0);
	assert(find("block in quick on ra1 from any to 10.8.0.0/24\n") >= 0);
	/* "lan" must not match "lanx" */
	nrules = 0;
	net_extra_fw_flushed();
	strcpy(cfg[CFG_SYS_NET2_REACH], "lanx,wgx");
	net_extra_fw_rules(collect);
	assert(find("block in quick on ra1 from any to 10.0.1.0/24\n") >= 0 && find("block in quick on ra1 from any to 10.8.0.0/24\n") >= 0);
	/* Internet through the WireGuard tunnel: local rules first, then route-to wg0 */
	nrules = 0;
	net_extra_fw_flushed();
	strcpy(cfg[CFG_SYS_NET2_REACH], "lan");
	strcpy(cfg[CFG_SYS_NET2_VIA], "wg");
	strcpy(cfg[CFG_SYS_NET3_VIA], "wg"); /* no Internet: no route-to */
	net_extra_fw_rules(collect);
	assert(net_extra_via_wg(2) && net_extra_via_wg(3) && !net_extra_via_wg(4));
	{
		int pass_lan = find("pass in quick on ra1 from any to 10.0.1.0/24\n"), to_wg = find("pass in quick on ra1 to wg0 from any to any\n");
		int block_dev = find("block in quick on ra1 from any to 10.0.2.1/32\n"), block_n3 = find("block in quick on ra1 from any to 10.0.3.0/24\n");
		assert(pass_lan >= 0 && to_wg > pass_lan && block_dev >= 0 && block_dev < to_wg && block_n3 < to_wg);
	}
	assert(find("pass in quick on ra2 to wg0 from any to any\n") < 0);
	/* LAN address not known yet (bridge-based LAN before its lease): no "/0" blocks */
	{
		unsigned long sip = SYS_lan_ip, smask = SYS_lan_mask;
		int k;
		SYS_lan_ip = 0; SYS_lan_mask = 0;
		nrules = 0;
		net_extra_fw_flushed();
		net_extra_fw_rules(collect);
		assert(nrules > 0);
		for (k = 0; k < nrules; k++) assert(!strstr(rules[k], "/0\n"));
		SYS_lan_ip = sip; SYS_lan_mask = smask;
	}
	/* the Ethernet port in routed network 2 (Wi-Fi uplink): same rules on eth1 */
	strcpy(cfg[CFG_SYS_OPMODE], "2"); strcpy(cfg[CFG_WLN_ApCliEnable], "1"); strcpy(cfg[CFG_SYS_ETH_NET], "2");
	assert(net_extra_eth_net() == 2);
	nrules = 0;
	net_extra_fw_flushed();
	net_extra_fw_rules(collect);
	assert(find("pass out quick on eth1 from any to any keep state\n") >= 0);
	/* the port is the same network: never blocked from its own range */
	assert(find("block in quick on eth1 from any to 10.0.2.0/24\n") < 0 && find("block in quick on ra1 from any to 10.0.2.0/24\n") < 0);
	assert(find("pass out quick on ra1 from any to any keep state\n") >= 0);
	strcpy(cfg[CFG_SYS_NET2_IP], ""); assert(net_extra_eth_net() == 0);   /* bridged network: no */
	strcpy(cfg[CFG_SYS_NET2_IP], "10.0.2.1/24");
	strcpy(cfg[CFG_SYS_OPMODE], "1"); assert(net_extra_eth_net() == 0);   /* cable uplink: the port is the WAN */
	strcpy(cfg[CFG_SYS_OPMODE], "2"); strcpy(cfg[CFG_SYS_ETH_NET], "");
	/* network 1 is routed only in bridge-based setups (opmode 3) */
	strcpy(cfg[CFG_SYS_NET1_IP], "10.0.9.1/24");
	strcpy(cfg[CFG_SYS_OPMODE], "2");
	assert(!net_extra_routed(1, 0, 0));
	strcpy(cfg[CFG_SYS_OPMODE], "3");
	assert(net_extra_routed(1, 0, 0) && net_extra_bridge_base());
	assert(net_extra_ifnames(names, 7) >= 1 && !strcmp(names[0], "ra0"));
	strcpy(cfg[CFG_SYS_NET1_IP], "");
	assert(!net_extra_routed(1, 0, 0));
	puts("PASS: routed networks, address parsing and isolation rules (reach list, Internet, device access, via WireGuard, network 1 in bridge setups)");
	return 0;
}
