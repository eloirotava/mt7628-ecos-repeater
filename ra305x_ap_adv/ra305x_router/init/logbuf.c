/* Console log in RAM and to a remote syslog server.
 * Every character written with diag_printf (WireGuard, WSS, mDNS, DHCP,
 * routed networks ...) also goes into an 8 KB ring, shown by GET /log.html,
 * and complete lines are sent once a second as syslog over UDP to
 * SYS_LOG_SERVER ("a.b.c.d" or "a.b.c.d:port", default port 514; empty: off),
 * e.g. the WireGuard server, so the device can be followed without a serial
 * cable. Plain printf() output of the SDK is not captured. */
#ifndef LOGBUF_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <cyg/infra/diag.h>
#include <network.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#endif
#include "logbuf.h"

#define LOG_SIZE 8192 /* power of two */

static char ring[LOG_SIZE];
static volatile unsigned long head; /* total characters ever written */

void logbuf_putc(char c)
{
	ring[head & (LOG_SIZE - 1)] = c;
	head++;
}

/* The last characters in order into out (up to size - 1); returns the length. */
int logbuf_read(char *out, int size)
{
	unsigned long h = head, start, i;
	int n;
	if (size <= 0) return 0;
	n = h < LOG_SIZE ? (int)h : LOG_SIZE;
	if (n > size - 1) n = size - 1;
	start = h - (unsigned long)n;
	for (i = 0; i < (unsigned long)n; i++) out[i] = ring[(start + i) & (LOG_SIZE - 1)];
	out[n] = 0;
	return n;
}

/* "a.b.c.d[:port]" -> address and port (network order); 0 if valid */
int logbuf_parse_server(const char *s, unsigned long *ip, unsigned short *port)
{
	char a[20];
	const char *c = strchr(s, ':');
	size_t l = c ? (size_t)(c - s) : strlen(s);
	struct in_addr in;
	long p = 514;
	if (!l || l >= sizeof a) return -1;
	memcpy(a, s, l);
	a[l] = 0;
	if (!inet_aton(a, &in) || !in.s_addr) return -1;
	if (c) {
		char *end;
		p = strtol(c + 1, &end, 10);
		if (*end || p < 1 || p > 65535) return -1;
	}
	*ip = in.s_addr;
	*port = htons((unsigned short)p);
	return 0;
}

#ifndef LOGBUF_HOST_TEST
extern int CFG_get_str(int id, char *val);

static void log_putc(char c, void **param)
{
	(void)param;
	logbuf_putc(c);
	diag_write_char(c);
}

static cyg_handle_t log_handle;
static cyg_thread log_obj;
static char log_stack[4096];

/* sends the complete lines written since the last call */
static void log_thread(cyg_addrword_t arg)
{
	static char line[300], pkt[340], name[64];
	unsigned long sent;
	int s = -1;
	(void)arg;
	sent = head;
	for (;;) {
		char cfg[40];
		unsigned long ip, h;
		unsigned short port;
		int n = 0;
		cyg_thread_delay(100);
		cfg[0] = 0;
		CFG_get_str(CFG_SYS_LOG_SERVER, cfg);
		h = head;
		if (!cfg[0] || logbuf_parse_server(cfg, &ip, &port)) { sent = h; continue; }
		if (h - sent > LOG_SIZE) sent = h - LOG_SIZE; /* overwritten: skip ahead */
		if (s < 0 && (s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) continue;
		name[0] = 0;
		CFG_get_str(CFG_SYS_MDNS_NAME, name);
		while (sent < h) {
			char c = ring[sent & (LOG_SIZE - 1)];
			sent++;
			if (c == '\r') continue;
			if (c != '\n' && n < (int)sizeof line - 1) { line[n++] = c; continue; }
			if (c != '\n') continue; /* overlong line: rest dropped */
			if (n) {
				struct sockaddr_in to;
				int m;
				line[n] = 0;
				/* <14>: facility user, severity info */
				m = snprintf(pkt, sizeof pkt, "<14>%s: %s", name[0] ? name : "extender", line);
				memset(&to, 0, sizeof to);
				to.sin_len = sizeof to;
				to.sin_family = AF_INET;
				to.sin_addr.s_addr = ip;
				to.sin_port = port;
				sendto(s, pkt, m < (int)sizeof pkt ? m : (int)sizeof pkt - 1, 0, (struct sockaddr *)&to, sizeof to);
			}
			n = 0;
		}
		/* a partial line stays in the ring: send it with the rest next time */
		sent -= n;
	}
}

/* as early as possible: the boot messages go into the ring too */
void logbuf_capture(void)
{
	diag_init_putc(log_putc);
}

/* after the configuration is loaded: the sender reads SYS_LOG_SERVER */
void logbuf_start(void)
{
	cyg_thread_create(15, log_thread, 0, "syslog", log_stack, sizeof log_stack, &log_handle, &log_obj);
	cyg_thread_resume(log_handle);
}
#endif
