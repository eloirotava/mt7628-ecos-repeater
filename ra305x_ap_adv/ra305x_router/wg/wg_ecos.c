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
#include "util.h" /* dns_resolve, tcp_open, unhex32 */
#include "sys.h"
#include "tls13.h"
#include "ws.h"
#include "crypto_ecos.h"

extern int CFG_get_str(int id, char *val);
extern int CFG_set_str(int id, char *val);
extern int CFG_commit(int id);
extern int CFG_save_user(void);
extern long x_getrandom(void *b, size_t n);     /* crypto entropy pool */
extern cyg_bool_t netif_alias_cfg(const char *intf, struct ip_set *setp);
extern void CFG_get_mac(int id, char *dp);

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
static int if_ready; /* wg0 attached and addressed */

static cyg_handle_t rx_handle, tx_handle;
static cyg_thread rx_obj, tx_obj;
/* rx also runs the TLS handshake (X25519, Ed25519, SHA-512) for wss */
static char rx_stack[16384], tx_stack[8192];
static unsigned char rx_buf[1600], rx_plain[1600], tx_plain[1500], tx_buf[1600];

static long uptime(void) { return (long)(cyg_current_time() / 100); }

static char wss_error[160]; /* last WSS problem, kept after a fallback to UDP */
const char *wg_ecos_wss_error(void) { return wss_error; }

/* Watchdog: with SYS_WG_WATCHDOG minutes > 0, restart the device when the
 * tunnel has had no session for that long (counted from start-up or from the
 * last connected moment). A restart retries everything from scratch (uplink,
 * DHCP, DNS, WSS) and needs nobody on site. */
static long wd_ok;          /* uptime of the last moment with a session */
static int wd_minutes, wd_fired;
static void watchdog_tick(void)
{
	long now = (long)(cyg_current_time() / 100);
	if (!wd_minutes || wd_fired) return;
	if (state == WG_CONNECTED) { wd_ok = now; return; }
	if (now - wd_ok >= (long)wd_minutes * 60) {
		wd_fired = 1;
		diag_printf("wg: no session for %d minutes, restarting (watchdog)\n", wd_minutes);
		mon_snd_cmd(MON_CMD_REBOOT);
	}
}
int wg_ecos_watchdog_minutes(void) { return wd_minutes; }

static void set_status(int s, const char *m)
{
	if (!strncmp(m, "WSS:", 4)) { strncpy(wss_error, m, sizeof wss_error - 1); wss_error[sizeof wss_error - 1] = 0; }
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

/* UNIX time from SNTP (0 while unknown); with sync, asks SNTP when unknown.
 * Shared with the network schedule (init/sched.c). */
long wg_ecos_unix_time(int sync)
{
	if (!clock_base_unix && sync && sntp_sync() == 0) diag_printf("time: clock synchronized\n");
	return clock_base_unix ? clock_base_unix + uptime() - clock_base_up : 0;
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

/* wss transport: each WireGuard datagram is one binary WebSocket frame,
 * TLS 1.3 to the server pinned by its Ed25519 key (wstunnel v10 dialect).
 * Writers hold `lock`; the rx thread reads without it. A KeyUpdate answered
 * inside tls_read could race a write, but the server (rustls) never asks. */
static int wss, wss_fd = -1, wss_fails;
static long wss_since;      /* start of the current attempt to get a session over WSS */
#define WSS_GIVE_UP 180     /* seconds without a session before falling back to UDP */
static char wss_host[80], wss_name[80], wss_path[96];
static uint8_t wss_key[32];
static unsigned wss_port;
static tls_conn wss_conn;
static uint8_t wss_rx[4096], wss_out[sizeof tx_buf + 14];
static size_t wss_rx_len;

static void send_raw(const unsigned char *b, size_t n)
{
	if (wss) {
		if (wss_fd >= 0 && tls_write(&wss_conn, wss_out, ws_frame(wss_out, 2, b, n))) {
			/* broken: the rx thread notices on its next read and reconnects */
			shutdown(wss_fd, SHUT_RDWR);
		}
	} else {
		sendto(sock, b, n, 0, (struct sockaddr *)&peer_addr, sizeof peer_addr);
	}
	last_tx = uptime();
}

/* TCP + TLS + WebSocket upgrade; 0 or -1 (status says why) */
static int wss_connect(void)
{
	static char req[640];
	char claims[96], m[160];
	uint8_t ip[4];
	struct sockaddr_in a;
	const char *err;
	long n, r;
	size_t i, end = 0;
	int fd, one = 1, recs = 0, ctl = 0;
	const char *why = "failed";
	char first[17];

	if (dns_resolve(wss_host, ip)) { set_status(WG_HANDSHAKE, "WSS: endpoint name not resolved"); return -1; }
	addr4(&a, ip, 443);
	a.sin_len = sizeof a;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		snprintf(m, sizeof m, "WSS: no free socket (errno %d)", errno);
		set_status(WG_HANDSHAKE, m);
		return -1;
	}
	{
		struct timeval tv = { 15, 0 };
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
	}
	if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
		snprintf(m, sizeof m, "WSS: TCP connection to %s:443 failed (errno %d)", inet_ntoa(a.sin_addr), errno);
		set_status(WG_HANDSHAKE, m);
		close(fd);
		return -1;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	err = tls_handshake(&wss_conn, fd, wss_name, 0, 0, wss_key, x_now() + 30);
	if (err) {
		snprintf(m, sizeof m, "WSS: TLS failed (%s)", err);
		set_status(WG_HANDSHAKE, m);
		close(fd);
		return -1;
	}
	snprintf(claims, sizeof claims, "\",\"p\":{\"Udp\":{\"timeout\":null}},\"r\":\"127.0.0.1\",\"rp\":%u}", wss_port);
	n = ws_request(req, sizeof req, wss_path, wss_name, claims);
	wss_rx_len = 0;
	if (n < 0 || tls_write(&wss_conn, (const uint8_t *)req, (size_t)n)) { why = "sending the request"; goto fail; }
	while (!end) {
		r = tls_read(&wss_conn, wss_rx + wss_rx_len, sizeof wss_rx - wss_rx_len);
		recs++;
		if (r < 0) { why = "no reply (timeout or closed)"; goto fail; }
		if (r == 0) ctl++;
		wss_rx_len += (size_t)r;
		for (i = 0; i + 4 <= wss_rx_len && !end; i++)
			if (!memcmp(wss_rx + i, "\r\n\r\n", 4)) end = i + 4;
		if (!end && wss_rx_len == sizeof wss_rx) { why = "reply too long"; goto fail; }
	}
	if (memcmp(wss_rx, "HTTP/1.1 101", 12)) {
		set_status(WG_HANDSHAKE, "WSS: WebSocket upgrade refused (check the path)");
		close(fd);
		return -1;
	}
	wss_rx_len -= end;
	memmove(wss_rx, wss_rx + end, wss_rx_len);
	{
		/* from now on reads wake up every second for the WireGuard timers */
		struct timeval tv = { 1, 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}
	memcpy(&peer_addr, &a, sizeof a);
	cyg_mutex_lock(&lock);
	wss_fd = fd;
	cyg_mutex_unlock(&lock);
	return 0;
fail:
	/* what came back, for the state's wss_error */
	for (i = 0; i < 16 && i < wss_rx_len; i++) first[i] = wss_rx[i] >= 32 && wss_rx[i] < 127 ? wss_rx[i] : '.';
	first[i] = 0;
	snprintf(m, sizeof m, "WSS: upgrade %s; %d records (%d control), %u bytes [%s]", why, recs, ctl, (unsigned)wss_rx_len, first);
	set_status(WG_HANDSHAKE, m);
	close(fd);
	return -1;
}

/* WSS did not give a session in time: carry on over UDP until the next
 * restart, so the device stays reachable through the tunnel. */
static int wss_to_udp(void)
{
	struct timeval tv = { 1, 0 };
	uint8_t ip[4];
	int s;
	if (dns_resolve(wss_host, ip)) return -1;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	cyg_mutex_lock(&lock);
	if (wss_fd >= 0) close(wss_fd);
	wss_fd = -1;
	memset(&peer_addr, 0, sizeof peer_addr);
	peer_addr.sin_len = sizeof peer_addr;
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons((unsigned short)wss_port);
	memcpy(&peer_addr.sin_addr, ip, 4);
	sock = s;
	wss = 0;
	init_time = -1;
	cyg_mutex_unlock(&lock);
	set_status(WG_HANDSHAKE, "WSS did not connect in 3 minutes; using UDP until the next restart");
	diag_printf("wg: WSS gave up, falling back to UDP\n");
	return 0;
}

static void wss_drop(void)
{
	cyg_mutex_lock(&lock);
	if (wss_fd >= 0) close(wss_fd);
	wss_fd = -1;
	cyg_mutex_unlock(&lock);
}

/* next datagram into d: length, 0 after ~1 s without one, -1 if the
 * connection is gone */
static const char *wss_why = ""; /* which step of wss_recv gave up */
static long wss_up;              /* uptime when the WebSocket opened */

static long wss_recv(uint8_t *d, size_t cap)
{
	for (;;) {
		int op;
		size_t off, pl;
		long t = ws_parse(wss_rx, wss_rx_len, sizeof wss_rx, &op, &off, &pl), r;
		if (t < 0) { wss_why = "invalid WebSocket frame"; return -1; }
		if (t > 0) {
			r = -2;
			if (op == 2 && pl <= cap) { memcpy(d, wss_rx + off, pl); r = (long)pl; }
			if (op == 9) {
				cyg_mutex_lock(&lock);
				tls_write(&wss_conn, wss_out, ws_frame(wss_out, 0xA, wss_rx + off, pl));
				cyg_mutex_unlock(&lock);
			}
			if (op == 8) { wss_why = "server closed the WebSocket"; return -1; }
			wss_rx_len -= (size_t)t;
			memmove(wss_rx, wss_rx + t, wss_rx_len);
			if (r >= 0) return r;
			continue;
		}
		/* no select(): on this stack it reported data that was not there and
		 * the read then blocked; the socket has a 1 s receive timeout instead
		 * and an incomplete record is resumed on the next call */
		errno = 0;
		r = tls_read(&wss_conn, wss_rx + wss_rx_len, sizeof wss_rx - wss_rx_len);
		if (r == TLS_AGAIN) return 0;
		if (r < 0) { wss_why = "TLS read failed"; return -1; }
		wss_rx_len += (size_t)r;
	}
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

	if (!wss) setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	wss_since = uptime();
	for (;;) {
		if (wss) {
			/* no WireGuard session over WSS for 3 minutes: fall back to UDP */
			if (state != WG_CONNECTED && uptime() - wss_since > WSS_GIVE_UP && !wss_to_udp())
				continue;
			if (wss_fd < 0) {
				if (wss_connect()) {
					/* 5 s, 10 s, 20 s ... up to 60 s between attempts */
					int d = 500 << (wss_fails < 4 ? wss_fails : 4);
					wss_fails++;
					cyg_thread_delay(d > 6000 ? 6000 : d);
					continue;
				}
				wss_fails = 0;
				wss_up = uptime();
				init_time = -1; /* new path: handshake again right away */
			}
			n = wss_recv(rx_buf, sizeof rx_buf);
			if (n < 0) {
				char why[160];
				snprintf(why, sizeof why, "WSS: connection lost (%s, errno %d, %ld s after opening); reconnecting",
				         wss_why, errno, uptime() - wss_up);
				wss_drop();
				if (state == WG_CONNECTED) wss_since = uptime(); /* a working path gets 3 more minutes */
				set_status(WG_HANDSHAKE, why);
				continue;
			}
		} else {
			n = recv(sock, rx_buf, sizeof rx_buf, 0);
		}
		now = uptime();
		watchdog_tick();
		cyg_mutex_lock(&lock);
		if (n > 0) {
			switch (wg_msg_type(rx_buf, (size_t)n)) {
			case 2:
				if (!wg_consume_response(&wg, rx_buf, (size_t)n)) {
					sess_time = now;
					init_time = -1;
					snprintf(m, sizeof m, wss ? "Connected to %s:%u (WSS)" : "Connected to %s:%u", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
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
	int enabled, have_psk, port, tries, enabled_seed_dirty;
	unsigned char ip_mac[6];
	(void)arg;

	set_status(WG_STARTING, "Starting");
	/* entropy: saved seed, MAC, then timer jitter (about 5 s) */
	val[0] = 0;
	CFG_get_str(CFG_SYS_RND_SEED, val);
	crypto_entropy_add(val, strlen(val));
	CFG_get_mac(0, (char *)ip_mac);
	crypto_entropy_add(ip_mac, sizeof ip_mac);
	crypto_entropy_collect();
	enabled_seed_dirty = 0;

	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_KEY, val);
	if (wg_b64_decode32(key, val)) {
		x_getrandom(key, 32);
		key[0] &= 248; key[31] = (key[31] & 127) | 64; /* X25519 clamping */
		wg_b64_encode32(val, key);
		CFG_set_str(CFG_SYS_WG_KEY, val);
		enabled_seed_dirty = 1;
	}
	x25519_base(pub, key);
	wg_b64_encode32(pub_b64, pub);
	have_key = 1;

	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_EN, val);
	enabled = atoi(val) == 1;
	/* renew the seed so the next boot does not start from the same state;
	 * only when something is written anyway or the tunnel is in use */
	if (enabled || enabled_seed_dirty) {
		uint8_t seed[32];
		x_getrandom(seed, 32);
		wg_b64_encode32(val, seed);
		memset(seed, 0, sizeof seed);
		CFG_set_str(CFG_SYS_RND_SEED, val);
		CFG_commit(CFG_NO_EVENT);
		if (CFG_save_user()) diag_printf("wg: saving key/seed failed\n");
	}
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
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_TRANSPORT, val);
	wss = !strcmp(val, "wss");
	if (wss) {
		wss_port = (unsigned)port;
		strncpy(wss_host, host, sizeof wss_host - 1);
		wss_path[0] = wss_name[0] = 0;
		CFG_get_str(CFG_SYS_WG_WSS_PATH, val);
		strncpy(wss_path, val, sizeof wss_path - 1);
		CFG_get_str(CFG_SYS_WG_WSS_NAME, val);
		strncpy(wss_name, val[0] ? val : host, sizeof wss_name - 1);
		val[0] = 0;
		CFG_get_str(CFG_SYS_WG_WSS_KEY, val);
		if (wss_path[0] != '/' || unhex32(wss_key, val)) { set_status(WG_ERROR, "Not started: WSS needs a path and the server's Ed25519 key"); return; }
	}
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_WATCHDOG, val);
	wd_minutes = atoi(val);
	if (wd_minutes < 0 || wd_minutes > 1440) wd_minutes = 0;
	wd_ok = uptime();
	CFG_get_str(CFG_SYS_WG_KEEPALIVE, val);
	keepalive = (unsigned)atoi(val);
	if (keepalive > 3600) keepalive = 25;

	wg_init(&wg, key, peer, have_psk ? psk : 0);
	memset(key, 0, sizeof key);
	memset(psk, 0, sizeof psk);

	/* interface first, so the address and route exist even before the peer answers */
	if (!if_ready) {
		cyg_mutex_init(&lock);
		cyg_semaphore_init(&tx_wake, 0);
		wg_if_attach(&tx_wake);
		if (!netif_alias_cfg("wg0", &addr)) { set_status(WG_ERROR, "Could not configure wg0"); return; }
		if_ready = 1;
	}

	set_status(WG_CLOCK, "Waiting for network time (SNTP) and the endpoint address");
	for (tries = 0; ; tries++) {
		watchdog_tick();
		if (!clock_base_unix && sntp_sync() == 0) diag_printf("wg: clock synchronized\n");
		if (clock_base_unix && !dns_resolve(host, ip)) break;
		cyg_thread_delay(tries < 6 ? 500 : 3000);
	}
	memset(&peer_addr, 0, sizeof peer_addr);
	peer_addr.sin_len = sizeof peer_addr;
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons((unsigned short)port);
	memcpy(&peer_addr.sin_addr, ip, 4);

	if (!wss) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) { set_status(WG_ERROR, "Could not open the UDP socket"); return; }
	}

	cyg_thread_create(11, tx_thread, 0, "wg tx", tx_stack, sizeof tx_stack, &tx_handle, &tx_obj);
	cyg_thread_resume(tx_handle);
	cyg_thread_create(11, rx_thread, 0, "wg rx", rx_stack, sizeof rx_stack, &rx_handle, &rx_obj);
	cyg_thread_resume(rx_handle);
}

static cyg_handle_t boot_handle;
static cyg_thread boot_obj;
static char boot_stack[12288];

/* wg0 is created at start-up (not after the ~5 s entropy collection) so
 * that NAT and firewall rules naming wg0 (routed networks sent through the
 * tunnel) find the interface when they are loaded. */
static void early_interface(void)
{
	char val[64];
	struct ip_set addr;
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_EN, val);
	if (atoi(val) != 1) return;
	val[0] = 0;
	CFG_get_str(CFG_SYS_ADMPASS, val);
	if (!val[0]) return;
	val[0] = 0;
	CFG_get_str(CFG_SYS_WG_ADDR, val);
	if (parse_cidr(val, &addr)) return;
	cyg_mutex_init(&lock);
	cyg_semaphore_init(&tx_wake, 0);
	wg_if_attach(&tx_wake);
	if (netif_alias_cfg("wg0", &addr)) if_ready = 1;
}

void wg_ecos_start(void)
{
	early_interface();
	cyg_thread_create(14, boot_thread, 0, "wg boot", boot_stack, sizeof boot_stack, &boot_handle, &boot_obj);
	cyg_thread_resume(boot_handle);
}
