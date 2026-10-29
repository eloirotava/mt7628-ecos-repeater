/* Minimal mDNS responder: answers A (and ANY) questions for
 * "<SYS_MDNS_NAME>.local" with this device's address on the asker's subnet,
 * so the device can be found as http://<name>.local/ without knowing its IP
 * (it changes with the upstream DHCP lease). Empty name: off.
 * Listens on 224.0.0.251:5353 on every address the device has (LAN, rescue,
 * routed networks); memberships are refreshed every minute because the LAN
 * address can change. Replies go to the group, or straight to the asker for
 * one-shot ("legacy unicast") queries from a port other than 5353. */
#ifndef MDNS_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <cfg_def.h>
#include <cfg_id.h>
#endif
#include "mdns.h"

#define MDNS_PORT 5353
#define MDNS_TTL  120

/* Name in a DNS question equal to "<name>.local" (labels, any case)? Returns
 * the length of the encoded name, 0 if it does not match, -1 if malformed. */
int mdns_match(const unsigned char *p, int left, const char *name)
{
	int off = 0, label = 0, nl = (int)strlen(name);
	while (off < left) {
		int l = p[off];
		if (l == 0) return label == 2 ? off + 1 : 0;
		if (l & 0xc0) return -1; /* no compression in questions we answer */
		if (off + 1 + l > left) return -1;
		if (label == 0) {
			int i;
			if (l != nl) return 0;
			for (i = 0; i < l; i++)
				if (tolower(p[off + 1 + i]) != tolower((unsigned char)name[i])) return 0;
		} else if (label == 1) {
			int i;
			if (l != 5) return 0;
			for (i = 0; i < 5; i++)
				if (tolower(p[off + 1 + i]) != "local"[i]) return 0;
		} else return 0;
		label++;
		off += 1 + l;
	}
	return -1;
}

/* Builds the answer for one matching question; returns its length. */
int mdns_answer(unsigned char *out, unsigned short id, const unsigned char *qname, int qlen,
                int with_question, unsigned long addr)
{
	int n = 0;
	out[n++] = id >> 8; out[n++] = id & 0xff;
	out[n++] = 0x84; out[n++] = 0x00;            /* response, authoritative */
	out[n++] = 0; out[n++] = with_question ? 1 : 0; /* questions */
	out[n++] = 0; out[n++] = 1;                  /* answers */
	out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 0;
	if (with_question) {
		memcpy(out + n, qname, qlen); n += qlen;
		out[n++] = 0; out[n++] = 1; out[n++] = 0; out[n++] = 1; /* A, IN */
	}
	memcpy(out + n, qname, qlen); n += qlen;
	out[n++] = 0; out[n++] = 1;                  /* A */
	out[n++] = 0x80; out[n++] = 1;               /* IN, cache flush */
	out[n++] = 0; out[n++] = 0; out[n++] = MDNS_TTL >> 8; out[n++] = MDNS_TTL & 0xff;
	out[n++] = 0; out[n++] = 4;
	memcpy(out + n, &addr, 4); n += 4;           /* network order already */
	return n;
}

#ifndef MDNS_HOST_TEST
extern int CFG_get_str(int id, char *val);

/* this device's IPv4 address on the same subnet as src (0: none) */
static unsigned long local_addr_for(unsigned long src)
{
	struct ifaddrs *list, *i;
	unsigned long best = 0;
	if (getifaddrs(&list) < 0) return 0;
	for (i = list; i; i = i->ifa_next) {
		unsigned long a, m;
		if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET || !i->ifa_netmask) continue;
		a = ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr;
		m = ((struct sockaddr_in *)i->ifa_netmask)->sin_addr.s_addr;
		if (!a || (a & 0xff) == 127) continue;
		if ((a & m) == (src & m)) { best = a; break; }
	}
	freeifaddrs(list);
	return best;
}

/* join the mDNS group on every address we have (errors for groups already
 * joined are expected) */
static void join_all(int s)
{
	struct ifaddrs *list, *i;
	if (getifaddrs(&list) < 0) return;
	for (i = list; i; i = i->ifa_next) {
		struct ip_mreq mr;
		if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
		mr.imr_interface = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
		if (!mr.imr_interface.s_addr || (mr.imr_interface.s_addr & 0xff) == 127) continue;
		mr.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
		setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr);
	}
	freeifaddrs(list);
}

/* for the state: what the responder is doing */
static const char *mdns_state = "not started";
static unsigned mdns_queries, mdns_answers, mdns_noaddr;
void mdns_status(const char **state, unsigned *queries, unsigned *answers, unsigned *noaddr)
{
	*state = mdns_state; *queries = mdns_queries; *answers = mdns_answers; *noaddr = mdns_noaddr;
}

static cyg_handle_t mdns_handle;
static cyg_thread mdns_obj;
static char mdns_stack[6144];

static void mdns_thread(cyg_addrword_t arg)
{
	static unsigned char in[512], out[512];
	struct sockaddr_in me, from, to;
	struct timeval tv = { 5, 0 };
	char name[64];
	int s, one = 1;
	long last_join = -1000;
	(void)arg;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { mdns_state = "no socket"; diag_printf("mdns: no socket\n"); return; }
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	memset(&me, 0, sizeof me);
	me.sin_len = sizeof me;
	me.sin_family = AF_INET;
	me.sin_port = htons(MDNS_PORT);
	if (bind(s, (struct sockaddr *)&me, sizeof me) < 0) { mdns_state = "bind failed"; diag_printf("mdns: bind failed\n"); close(s); return; }
	mdns_state = "listening";
	{
		unsigned char ttl = 255;
		setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
	}
	for (;;) {
		int fl = sizeof from;
		long now = (long)(cyg_current_time() / 100);
		int n, off, qd, k;
		if (now - last_join >= 60) { join_all(s); last_join = now; }
		n = recvfrom(s, in, sizeof in, 0, (struct sockaddr *)&from, &fl);
		if (n < 12) continue;
		mdns_queries++;
		if (in[2] & 0x80) continue;                      /* a response, not a question */
		name[0] = 0;
		CFG_get_str(CFG_SYS_MDNS_NAME, name);
		if (!name[0]) continue;                          /* off */
		qd = in[4] << 8 | in[5];
		off = 12;
		for (k = 0; k < qd && off < n; k++) {
			int len = mdns_match(in + off, n - off, name);
			unsigned short qtype;
			if (len < 0) break;
			if (len == 0) {
				/* skip a question for another name */
				while (off < n && in[off] && !(in[off] & 0xc0)) off += 1 + in[off];
				off += (off < n && (in[off] & 0xc0)) ? 2 : 1;
				off += 4;
				continue;
			}
			if (off + len + 4 > n) break;
			qtype = in[off + len] << 8 | in[off + len + 1];
			if (qtype == 1 || qtype == 255) {
				unsigned long addr = local_addr_for(from.sin_addr.s_addr);
				int legacy = ntohs(from.sin_port) != MDNS_PORT;
				int m;
				if (!addr) { mdns_noaddr++; break; }
				m = mdns_answer(out, legacy ? (unsigned short)(in[0] << 8 | in[1]) : 0, in + off, len, legacy, addr);
				memset(&to, 0, sizeof to);
				to.sin_len = sizeof to;
				to.sin_family = AF_INET;
				if (legacy) { to.sin_addr = from.sin_addr; to.sin_port = from.sin_port; }
				else {
					struct in_addr ifa;
					ifa.s_addr = addr;
					setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof ifa);
					to.sin_addr.s_addr = inet_addr("224.0.0.251");
					to.sin_port = htons(MDNS_PORT);
				}
				if (sendto(s, out, m, 0, (struct sockaddr *)&to, sizeof to) == m) mdns_answers++;
				break;                                   /* one answer per query */
			}
			off += len + 4;
		}
	}
}

void mdns_start(void)
{
	cyg_thread_create(14, mdns_thread, 0, "mdns", mdns_stack, sizeof mdns_stack, &mdns_handle, &mdns_obj);
	cyg_thread_resume(mdns_handle);
}
#endif
