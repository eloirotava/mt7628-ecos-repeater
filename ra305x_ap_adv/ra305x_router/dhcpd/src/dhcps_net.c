/* Small DHCP server for the extra (routed) Wi-Fi networks, one pool per
 * interface (ra0..ra6); the main dhcpd keeps serving the LAN. Reuses the
 * dhcpd packet layer: per-interface packet sockets (UDP to port 67),
 * checksum checks, option helpers and raw Ethernet replies.
 * Pool: .100-.199 of the interface network, 12 h leases, 32 per network. */
#include <cyg/kernel/kapi.h>
#include <unistd.h>
#include <network.h>
#include <arpa/inet.h>
#include <sys/mbuf.h>
#include <netinet/ip_var.h>
#include <stdlib.h>
#include <string.h>
#include <sys_status.h>
#include <lib_packet.h>
#include <dhcpd.h>
#include <common_subr.h>
#include <packet.h>
#include <cfg_dns.h>

extern int LIB_etherpacket_send(struct ifnet *ifp, struct mbuf *m, unsigned char *dst_hwaddr, char *data, int len);
extern struct ifnet *ifunit(const char *name);

#define NETS        7
#define LEASES      32
#define LEASE_SECS  43200
#define POOL_FIRST  100
#define POOL_LAST   199

struct lease { unsigned char mac[6]; unsigned long ip; long expires; };
struct net {
	char ifname[8];
	struct ifnet *ifp;
	unsigned long ip, mask, dns; /* network byte order */
	int sock;
	/* the Ethernet port when it is part of this network (same pool and
	 * leases; replies go out on the port the request came in on) */
	char ifname2[8];
	struct ifnet *ifp2;
	int sock2;
	struct lease leases[LEASES];
};

static struct net nets[NETS];
static int n_nets;
static cyg_mutex_t lock;
static int started;
static cyg_handle_t thread_handle;
static cyg_thread thread_obj;
static char thread_stack[8192];

static long now(void) { return (long)(cyg_current_time() / 100); }

static int in_pool(struct net *n, unsigned long ip)
{
	unsigned long h = ntohl(ip), base = ntohl(n->ip & n->mask), last = ntohl(n->ip | ~n->mask) - 1;
	unsigned long first = base + POOL_FIRST, end = base + POOL_LAST;
	if (end > last) end = last;
	return (ip & n->mask) == (n->ip & n->mask) && h >= first && h <= end && ip != n->ip;
}

static struct lease *by_mac(struct net *n, const unsigned char *mac)
{
	int i;
	for (i = 0; i < LEASES; i++)
		if (n->leases[i].ip && !memcmp(n->leases[i].mac, mac, 6)) return &n->leases[i];
	return 0;
}

static int ip_taken(struct net *n, unsigned long ip, const unsigned char *mac)
{
	int i;
	for (i = 0; i < LEASES; i++)
		if (n->leases[i].ip == ip && memcmp(n->leases[i].mac, mac, 6) && n->leases[i].expires > now()) return 1;
	return 0;
}

/* Lease for mac: existing one, else the requested address, else the first free. */
static struct lease *assign(struct net *n, const unsigned char *mac, unsigned long want)
{
	struct lease *l = by_mac(n, mac), *slot = 0;
	unsigned long h, base, end, ip;
	int i;
	if (l) return l;
	for (i = 0; i < LEASES; i++)
		if (!n->leases[i].ip || n->leases[i].expires <= now()) { slot = &n->leases[i]; break; }
	if (!slot) return 0;
	ip = 0;
	if (want && in_pool(n, want) && !ip_taken(n, want, mac)) ip = want;
	base = ntohl(n->ip & n->mask);
	end = base + POOL_LAST;
	for (h = base + POOL_FIRST; !ip && h <= end; h++)
		if (in_pool(n, htonl(h)) && !ip_taken(n, htonl(h), mac)) ip = htonl(h);
	if (!ip) return 0;
	memcpy(slot->mac, mac, 6);
	slot->ip = ip;
	slot->expires = now() + 60; /* offered; extended on ACK */
	return slot;
}

static void reply(struct net *n, const struct dhcpd *req, int type, unsigned long yiaddr, struct ifnet *out)
{
	struct udp_dhcp_packet p;
	struct dhcpd *d = &p.data;
	unsigned long lease = htonl(LEASE_SECS), dst;
	unsigned char t = (unsigned char)type, *dst_mac;
	memset(&p, 0, sizeof p);
	d->op = BOOTREPLY;
	d->htype = 1;
	d->hlen = 6;
	d->xid = req->xid;
	d->flags = req->flags;
	d->ciaddr = req->ciaddr;
	d->yiaddr = yiaddr;
	d->siaddr = n->ip;
	memcpy(d->chaddr, req->chaddr, 16);
	d->cookie = htonl(DHCP_MAGIC);
	d->options[0] = DHCP_END;
	dhcpd_add_option(d->options, DHCP_MESSAGE_TYPE, 1, &t);
	dhcpd_add_option(d->options, DHCP_SERVER_ID, 4, &n->ip);
	if (type != DHCPNAK) {
		if (type != DHCPACK || yiaddr) dhcpd_add_option(d->options, DHCP_LEASE_TIME, 4, &lease);
		dhcpd_add_option(d->options, DHCP_SUBNET, 4, &n->mask);
		dhcpd_add_option(d->options, DHCP_ROUTER, 4, &n->ip);
		/* upstream DNS as of now: at boot the WAN may not have a lease yet */
		{
			unsigned long dns = n->dns ? n->dns : DNS_group_get(0);
			if (dns) dhcpd_add_option(d->options, DHCP_DNS_SERVER, 4, &dns);
		}
	}
	if (type != DHCPNAK && req->ciaddr) { dst = req->ciaddr; dst_mac = (unsigned char *)req->chaddr; }
	else { dst = INADDR_BROADCAST; dst_mac = MAC_BCAST_ADDR; }

	p.ip.ip_p = IPPROTO_UDP;
	p.ip.ip_src.s_addr = n->ip;
	p.ip.ip_dst.s_addr = dst;
	p.udp.uh_sport = htons(SERVER_PORT);
	p.udp.uh_dport = htons(CLIENT_PORT);
	p.udp.uh_ulen = htons(sizeof(p.udp) + sizeof(struct dhcpd));
	p.ip.ip_len = p.udp.uh_ulen; /* pseudo-header for the UDP checksum */
	p.udp.uh_sum = DHCPD_checksum(&p, sizeof p);
	p.ip.ip_len = htons(sizeof p);
	p.ip.ip_hl = sizeof(p.ip) >> 2;
	p.ip.ip_v = IPVERSION;
	p.ip.ip_ttl = IPDEFTTL;
	p.ip.ip_sum = DHCPD_checksum(&p.ip, sizeof(p.ip));
	{
		int rc = LIB_etherpacket_send(out, NULL, dst_mac, (char *)&p, sizeof p);
		diag_printf("dhcps %s: sent type %d to %s rc=%d\n", n->ifname, type, inet_ntoa(*(struct in_addr *)&yiaddr), rc);
	}
}

static void handle(struct net *n, struct dhcpd *req, struct ifnet *out)
{
	unsigned char type = 0;
	unsigned long want = 0, server = 0;
	struct lease *l;
	if (req->op != BOOTREQUEST || req->hlen != 6) return;
	if (!dhcpd_pickup_opt(req, DHCP_MESSAGE_TYPE, sizeof type, &type)) return;
	diag_printf("dhcps %s: got type %d from %02x:%02x:%02x:%02x:%02x:%02x\n", n->ifname, type, req->chaddr[0], req->chaddr[1], req->chaddr[2], req->chaddr[3], req->chaddr[4], req->chaddr[5]);
	dhcpd_pickup_opt(req, DHCP_REQUESTED_IP, sizeof want, &want);
	dhcpd_pickup_opt(req, DHCP_SERVER_ID, sizeof server, &server);
	switch (type) {
	case DHCPDISCOVER:
		if ((l = assign(n, req->chaddr, want))) reply(n, req, DHCPOFFER, l->ip, out);
		break;
	case DHCPREQUEST:
		if (server && server != n->ip) { l = by_mac(n, req->chaddr); if (l) l->ip = 0; break; } /* chose another server */
		if (!want) want = req->ciaddr; /* renewing */
		l = assign(n, req->chaddr, want);
		if (!l || l->ip != want) { reply(n, req, DHCPNAK, 0, out); break; }
		l->expires = now() + LEASE_SECS;
		reply(n, req, DHCPACK, l->ip, out);
		diag_printf("dhcps %s: %02x:%02x:%02x:%02x:%02x:%02x -> %s\n", n->ifname, req->chaddr[0], req->chaddr[1],
		            req->chaddr[2], req->chaddr[3], req->chaddr[4], req->chaddr[5], inet_ntoa(*(struct in_addr *)&l->ip));
		break;
	case DHCPRELEASE:
	case DHCPDECLINE:
		if ((l = by_mac(n, req->chaddr))) l->ip = 0;
		break;
	case DHCPINFORM:
		reply(n, req, DHCPACK, 0, out);
		break;
	}
}

/* DHCPD_PktCheck with a log line per DHCP packet seen (diagnostics) */
static int pkt_check(struct ifnet *ifp, char *head, struct mbuf *m, struct eth_input_func *hn)
{
	int r = DHCPD_PktCheck(ifp, head, m, hn), i, which = -1;
	for (i = 0; i < n_nets; i++) {
		if (nets[i].sock && ((struct pktsocket *)nets[i].sock)->handler == hn) which = i * 2;
		if (nets[i].sock2 && ((struct pktsocket *)nets[i].sock2)->handler == hn) which = i * 2 + 1;
	}
	if (r) diag_printf("dhcps hook %s%d: udp/67 r=%d len=%d socket %d\n", ifp->if_name, ifp->if_unit, r, m->m_pkthdr.len, which);
	return r;
}

static void server_thread(cyg_addrword_t arg)
{
	struct timeval tv;
	struct dhcpInfo info;
	int i, fd;
	(void)arg;
	for (;;) {
		cyg_mutex_lock(&lock);
		for (i = 0; i < n_nets; i++) {
			struct net *n = &nets[i];
			if (!n->sock) {
				n->sock = LIB_pktsocket_create(n->ifname, pkt_check);
				diag_printf("dhcps %s: packet socket %s\n", n->ifname, n->sock ? "ready" : "FAILED");
			}
			if (!n->sock) continue;
			/* LIB_pktsocket_deQ only honours tv_sec: 0 would never return a packet */
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			fd = DHCPD_rcv(n->sock, &tv, 0);
			if (fd == -1) diag_printf("dhcps %s: dropped (checksum/length)\n", n->ifname);
			if (fd > 0) {
				if (DHCPD_ReadPacket(&info, fd) > 0) handle(n, &info.payload, n->ifp);
				LIB_rcvinfo_close(fd);
			}
			if (n->ifp2) {
				if (!n->sock2) {
					n->sock2 = LIB_pktsocket_create(n->ifname2, pkt_check);
					diag_printf("dhcps %s: packet socket on %s %s\n", n->ifname, n->ifname2, n->sock2 ? "ready" : "FAILED");
				}
				if (!n->sock2) continue;
				tv.tv_sec = 1;
				tv.tv_usec = 0;
				fd = DHCPD_rcv(n->sock2, &tv, 0);
				if (fd == -1) diag_printf("dhcps %s: dropped from %s (checksum/length)\n", n->ifname, n->ifname2);
				if (fd > 0) {
					int rr = DHCPD_ReadPacket(&info, fd);
					diag_printf("dhcps %s: from %s read %d\n", n->ifname, n->ifname2, rr);
					if (rr > 0) handle(n, &info.payload, n->ifp2);
					LIB_rcvinfo_close(fd);
				}
			}
		}
		cyg_mutex_unlock(&lock);
		if (!n_nets) cyg_thread_delay(100);
	}
}

/* Serve ifname (already configured with ip/mask). dns: offered DNS server,
 * 0 for none. Calling again for the same interface updates it. */
int DHCPS_net_start(const char *ifname, unsigned long ip, unsigned long mask, unsigned long dns)
{
	struct net *n = 0;
	int i;
	if (!started) {
		cyg_mutex_init(&lock);
		cyg_thread_create(13, server_thread, 0, "dhcps net", thread_stack, sizeof thread_stack, &thread_handle, &thread_obj);
		cyg_thread_resume(thread_handle);
		started = 1;
	}
	cyg_mutex_lock(&lock);
	for (i = 0; i < n_nets; i++) if (!strcmp(nets[i].ifname, ifname)) n = &nets[i];
	if (!n && n_nets < NETS) { n = &nets[n_nets++]; memset(n, 0, sizeof *n); strncpy(n->ifname, ifname, sizeof n->ifname - 1); }
	if (n) {
		n->ifp = ifunit(ifname);
		if (n->ip != ip || n->mask != mask) memset(n->leases, 0, sizeof n->leases);
		n->ip = ip;
		n->mask = mask;
		n->dns = dns;
	}
	cyg_mutex_unlock(&lock);
	if (!n || !n->ifp) { diag_printf("dhcps %s: not started\n", ifname); return -1; }
	diag_printf("dhcps %s: serving %s\n", ifname, inet_ntoa(*(struct in_addr *)&ip));
	return 0;
}

/* The pool of ifname (started with DHCPS_net_start) also serves port, an
 * interface bridged with it (the Ethernet port in that network). */
int DHCPS_net_add_port(const char *ifname, const char *port)
{
	int i, rc = -1;
	cyg_mutex_lock(&lock);
	for (i = 0; i < n_nets; i++)
		if (!strcmp(nets[i].ifname, ifname)) {
			strncpy(nets[i].ifname2, port, sizeof nets[i].ifname2 - 1);
			nets[i].ifp2 = ifunit(port);
			rc = nets[i].ifp2 ? 0 : -1;
		}
	cyg_mutex_unlock(&lock);
	diag_printf("dhcps %s: %s %s\n", ifname, port, rc ? "not added" : "added");
	return rc;
}
