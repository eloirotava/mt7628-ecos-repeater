/* WireGuard client inside the MT7628KN extender firmware: configuration,
 * device key, clock (SNTP), handshake timers and the UDP side of wg0.
 *
 * One peer, initiator only. Settings (SYS_WG_*) are read at boot; the web
 * interface saves and restarts. The device key (SYS_WG_KEY) is generated on
 * the device, erased by a factory reset (a new one is made at the next
 * boot); only the public key is shown. */
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#include <cfg_net.h>
#include "wg_proto.h"
#include "wg_ecos.h"
#include "c25519.h"
#include "util.h" /* ntun: dns_resolve */

extern int CFG_get_str(int id, char *val);
extern int CFG_set_str(int id, char *val);
extern int CFG_commit(int id);
extern int CFG_save_user(void);
extern long x_getrandom(void *b, size_t n);     /* ntun entropy pool */
extern cyg_bool_t netif_alias_cfg(const char *intf, struct ip_set *setp);

#define REKEY_AFTER     120  /* s: start a new handshake */
#define REJECT_AFTER    180  /* s: stop using a session */
#define REKEY_TIMEOUT   5    /* s: retry an unanswered initiation */

static volatile int state = WG_OFF;
static char status[128] = "Disabled";
static char pub_b64[45];
static int have_key;

static wg_state wg;
static cyg_mutex_t lock;
static cyg_sem_t tx_wake;
static int sock = -1;
static struct sockaddr_in peer_addr;
static unsigned keepalive;
static long sess_time = -1, init_time = -1, last_tx;
static uint64_t last_tai_ns;
static long clock_base_unix, clock_base_up; /* unix = base_unix + (uptime - base_up) */

static cyg_handle_t rx_handle, tx_handle;
static cyg_thread rx_obj, tx_obj;
static char rx_stack[12288], tx_stack[8192];
static unsigned char rx_buf[1600], rx_plain[1600], tx_plain[1500], tx_buf[1600];

static long uptime(void) { return (long)(cyg_current_time() / 100); }

static void set_status(int s, const char *m)
{
	state = s;
	strncpy(status, m, sizeof status - 1);
	status[sizeof status - 1] = 0;
	diag_printf("wg: %s\n", status);
}

int wg_ecos_state(void) { return state; }
const char *wg_ecos_status(void) { return status; }
int wg_ecos_public_key(char b64[45]) { if (!have_key) { b64[0] = 0; return -1; } memcpy(b64, pub_b64, 45); return 0; }
long wg_ecos_handshake_age(void) { long t = sess_time; return t < 0 ? -1 : uptime() - t; }
void wg_ecos_counters(unsigned long *rx, unsigned long *tx) { wg_if_counters(rx, tx); }

/* ------------------------------------------------------------ base64 */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int wg_b64_decode32(unsigned char out[32], const char *s)
{
	unsigned long acc = 0;
	int bits = 0, n = 0, i;
	if (!s || strlen(s) != 44 || s[43] != '=') return -1;
	for (i = 0; i < 43; i++) {
		const char *p = strchr(B64, s[i]);
		if (!p || !*p) return -1;
		acc = (acc << 6 | (unsigned long)(p - B64)) & 0xffffff;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (n == 32) return -1;
			out[n++] = (unsigned char)(acc >> bits);
		}
	}
	return n == 32 ? 0 : -1;
}

void wg_b64_encode32(char out[45], const unsigned char in[32])
{
	int i, o = 0;
	for (i = 0; i < 30; i += 3) {
		unsigned long v = (unsigned long)in[i] << 16 | in[i + 1] << 8 | in[i + 2];
		out[o++] = B64[v >> 18 & 63]; out[o++] = B64[v >> 12 & 63];
		out[o++] = B64[v >> 6 & 63];  out[o++] = B64[v & 63];
	}
	{
		unsigned long v = (unsigned long)in[30] << 16 | in[31] << 8;
		out[o++] = B64[v >> 18 & 63]; out[o++] = B64[v >> 12 & 63];
		out[o++] = B64[v >> 6 & 63];  out[o++] = '=';
	}
	out[o] = 0;
}

/* ------------------------------------------------------------ clock */

/* SNTP (RFC 4330) against pool.ntp.org: transmit timestamp of the reply. */
static int sntp_sync(void)
{
	uint8_t ip[4], pkt[48];
	struct sockaddr_in a;
	struct timeval tv = { 3, 0 };
	int fd, n;
	unsigned long secs;

	if (dns_resolve("pool.ntp.org", ip)) return -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	memset(&a, 0, sizeof a);
	a.sin_len = sizeof a;
	a.sin_family = AF_INET;
	a.sin_port = htons(123);
	memcpy(&a.sin_addr, ip, 4);
	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x23; /* LI 0, version 4, client */
	sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&a, sizeof a);
	n = recv(fd, pkt, sizeof pkt, 0);
	close(fd);
	if (n < 48 || (pkt[0] & 7) != 4) return -1;
	secs = (unsigned long)pkt[40] << 24 | pkt[41] << 16 | pkt[42] << 8 | pkt[43];
	if (secs < 3900000000UL) return -1; /* before 2023: not a real answer */
	clock_base_unix = (long)(secs - 2208988800UL);
	clock_base_up = uptime();
	return 0;
}

/* Strictly increasing TAI64N, as the responder rejects replays. */
static void timestamp(uint8_t out[12])
{
	uint64_t ns = ((uint64_t)(clock_base_unix + uptime() - clock_base_up)) * 1000000000ULL
	              + (uint64_t)(cyg_current_time() % 100) * 10000000ULL;
	if (ns <= last_tai_ns) ns = last_tai_ns + 1;
	last_tai_ns = ns;
	wg_tai64n(out, ns / 1000000000ULL, (uint32_t)(ns % 1000000000ULL));
}

/* ------------------------------------------------------------ tunnel */

static void send_raw(const unsigned char *b, size_t n)
{
	sendto(sock, b, n, 0, (struct sockaddr *)&peer_addr, sizeof peer_addr);
	last_tx = uptime();
}

/* caller holds lock */
static void send_initiation(void)
{
	uint8_t rnd[32], ts[12], msg[WG_INIT_LEN];
	uint32_t index;
	x_getrandom(rnd, 32);
	x_getrandom(&index, 4);
	timestamp(ts);
	wg_make_initiation(&wg, msg, rnd, index, ts);
	memset(rnd, 0, sizeof rnd);
	send_raw(msg, sizeof msg);
	init_time = uptime();
	if (state != WG_CONNECTED) set_status(WG_HANDSHAKE, "Handshake sent; waiting for the peer");
}

static int session_usable(void)
{
	return wg.have_session && sess_time >= 0 && uptime() - sess_time < REJECT_AFTER;
}

static void tx_thread(cyg_addrword_t arg)
{
	int n;
	size_t m;
	(void)arg;
	for (;;) {
		cyg_semaphore_timed_wait(&tx_wake, cyg_current_time() + 100);
		while ((n = wg_if_dequeue(tx_plain, sizeof tx_plain)) != 0) {
			if (n < 0) continue;
			cyg_mutex_lock(&lock);
			if (session_usable()) {
				m = wg_encrypt(&wg, tx_plain, (size_t)n, tx_buf);
				send_raw(tx_buf, m);
			}
			cyg_mutex_unlock(&lock);
		}
	}
}

static void rx_thread(cyg_addrword_t arg)
{
	struct timeval tv = { 1, 0 };
	long n, p, now;
	char m[128];
	(void)arg;

	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	for (;;) {
		n = recv(sock, rx_buf, sizeof rx_buf, 0);
		now = uptime();
		cyg_mutex_lock(&lock);
		if (n > 0) {
			switch (wg_msg_type(rx_buf, (size_t)n)) {
			case 2:
				if (!wg_consume_response(&wg, rx_buf, (size_t)n)) {
					sess_time = now;
					init_time = -1;
					snprintf(m, sizeof m, "Connected to %s:%u", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
					set_status(WG_CONNECTED, m);
					/* confirm the session to the responder right away */
					send_raw(tx_buf, wg_encrypt(&wg, tx_plain, 0, tx_buf));
				}
				break;
			case 4:
				p = wg_decrypt(&wg, rx_buf, (size_t)n, rx_plain);
				if (p > 0) {
					cyg_mutex_unlock(&lock);
					wg_if_input(rx_plain, (int)p);
					cyg_mutex_lock(&lock);
				}
				break;
			default:
				break; /* initiations and cookie replies are not handled */
			}
		}
		/* timers */
		if (!wg.have_session || now - sess_time >= REKEY_AFTER) {
			if (init_time < 0 || now - init_time >= REKEY_TIMEOUT) send_initiation();
		}
		if (wg.have_session && sess_time >= 0 && now - sess_time >= REJECT_AFTER && state == WG_CONNECTED)
			set_status(WG_HANDSHAKE, "Session expired; peer not answering handshakes");
		if (keepalive && session_usable() && now - last_tx >= (long)keepalive)
			send_raw(tx_buf, wg_encrypt(&wg, tx_plain, 0, tx_buf));
		cyg_mutex_unlock(&lock);
	}
}

/* ------------------------------------------------------------ boot */

static int parse_cidr(const char *s, struct ip_set *set)
{
	char ip[20];
	const char *slash = strchr(s, '/');
	int bits;
	struct in_addr a;
	if (!slash || slash - s >= (int)sizeof ip) return -1;
	memcpy(ip, s, slash - s);
	ip[slash - s] = 0;
	bits = atoi(slash + 1);
	if (bits < 8 || bits > 32 || !inet_aton(ip, &a)) return -1;
	memset(set, 0, sizeof *set);
	set->ip = a.s_addr;
	set->netmask = htonl(bits == 32 ? 0xffffffffUL : ~(0xffffffffUL >> bits));
	return 0;
}

static void boot_thread(cyg_addrword_t arg)
{
	char val[256], host[80];
	uint8_t key[32], pub[32], peer[32], psk[32], ip[4];
	struct ip_set addr;
	int enabled, have_psk, port, tries;
	(void)arg;

	set_status(WG_STARTING, "Starting");
	/* the ntun thread collects entropy at boot; wait for it */
	for (tries = 0; x_getrandom(key, 1) < 0; tries++) {
		if (tries > 60) { set_status(WG_ERROR, "No random data available"); return; }
		cyg_thread_delay(100);
	}

	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_KEY, val);
	if (wg_b64_decode32(key, val)) {
		x_getrandom(key, 32);
		key[0] &= 248; key[31] = (key[31] & 127) | 64; /* X25519 clamping */
		wg_b64_encode32(val, key);
		CFG_set_str(CFG_SYS_WG_KEY, val);
		CFG_commit(CFG_NO_EVENT);
		if (CFG_save_user()) diag_printf("wg: saving the device key failed\n");
	}
	x25519_base(pub, key);
	wg_b64_encode32(pub_b64, pub);
	have_key = 1;

	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_EN, val);
	enabled = atoi(val) == 1;
	if (!enabled) { memset(key, 0, sizeof key); set_status(WG_OFF, "Disabled"); return; }

	CFG_get_str(CFG_SYS_ADMPASS, val);
	if (!val[0]) { memset(key, 0, sizeof key); set_status(WG_ERROR, "Not started: set an admin password first"); return; }

	CFG_get_str(CFG_SYS_WG_PEER, val);
	if (wg_b64_decode32(peer, val)) { set_status(WG_ERROR, "Not started: invalid peer public key"); return; }
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_PSK, val);
	have_psk = val[0] && !wg_b64_decode32(psk, val);
	CFG_get_str(CFG_SYS_WG_ADDR, val);
	if (parse_cidr(val, &addr)) { set_status(WG_ERROR, "Not started: invalid tunnel address"); return; }
	CFG_get_str(CFG_SYS_WG_HOST, host);
	CFG_get_str(CFG_SYS_WG_PORT, val);
	port = atoi(val);
	if (!host[0] || port < 1 || port > 65535) { set_status(WG_ERROR, "Not started: invalid endpoint"); return; }
	CFG_get_str(CFG_SYS_WG_KEEPALIVE, val);
	keepalive = (unsigned)atoi(val);
	if (keepalive > 3600) keepalive = 25;

	wg_init(&wg, key, peer, have_psk ? psk : 0);
	memset(key, 0, sizeof key);
	memset(psk, 0, sizeof psk);

	/* interface first, so the address and route exist even before the peer answers */
	cyg_mutex_init(&lock);
	cyg_semaphore_init(&tx_wake, 0);
	wg_if_attach(&tx_wake);
	if (!netif_alias_cfg("wg0", &addr)) { set_status(WG_ERROR, "Could not configure wg0"); return; }

	set_status(WG_CLOCK, "Waiting for network time (SNTP) and the endpoint address");
	for (tries = 0; ; tries++) {
		if (!clock_base_unix && sntp_sync() == 0) diag_printf("wg: clock synchronized\n");
		if (clock_base_unix && !dns_resolve(host, ip)) break;
		cyg_thread_delay(tries < 6 ? 500 : 3000);
	}
	memset(&peer_addr, 0, sizeof peer_addr);
	peer_addr.sin_len = sizeof peer_addr;
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons((unsigned short)port);
	memcpy(&peer_addr.sin_addr, ip, 4);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) { set_status(WG_ERROR, "Could not open the UDP socket"); return; }

	cyg_thread_create(11, tx_thread, 0, "wg tx", tx_stack, sizeof tx_stack, &tx_handle, &tx_obj);
	cyg_thread_resume(tx_handle);
	cyg_thread_create(11, rx_thread, 0, "wg rx", rx_stack, sizeof rx_stack, &rx_handle, &rx_obj);
	cyg_thread_resume(rx_handle);
}

static cyg_handle_t boot_handle;
static cyg_thread boot_obj;
static char boot_stack[12288];

void wg_ecos_start(void)
{
	cyg_thread_create(14, boot_thread, 0, "wg boot", boot_stack, sizeof boot_stack, &boot_handle, &boot_obj);
	cyg_thread_resume(boot_handle);
}
