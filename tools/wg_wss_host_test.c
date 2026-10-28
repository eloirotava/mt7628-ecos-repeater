/* Host test: WireGuard (wg/wg_proto.c) over the wstunnel WebSocket/TLS
 * transport (crypto/tls13.c, crypto/ws.c), against a real server.
 *   wg_wss_host_test <our-private-b64> <peer-public-b64> <wss-host> <path> <tls-name>
 *                    <server-ed25519-key-hex> <target-port> <tunnel-src-ip> <ping-dst-ip>
 * TLS is pinned by the server's Ed25519 key (no certificate copy). */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include "wg_proto.h"
#include "tls13.h"
#include "ws.h"
#include "util.h"

static int b64dec(uint8_t out[32], const char *s)
{
	static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t acc = 0;
	int bits = 0, n = 0;
	for (; *s && *s != '='; s++) {
		const char *p = strchr(a, *s);
		if (!p) return -1;
		acc = acc << 6 | (uint32_t)(p - a);
		bits += 6;
		if (bits >= 8) { bits -= 8; if (n == 32) return -1; out[n++] = (uint8_t)(acc >> bits); }
	}
	return n == 32 ? 0 : -1;
}

static uint16_t csum(const uint8_t *p, size_t n)
{
	uint32_t s = 0;
	for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)p[i] << 8 | p[i + 1];
	if (n & 1) s += (uint32_t)p[n - 1] << 8;
	while (s >> 16) s = (s & 0xffff) + (s >> 16);
	return (uint16_t)~s;
}

static size_t icmp_echo(uint8_t *pkt, uint32_t src, uint32_t dst, uint16_t seq)
{
	size_t n = 20 + 8 + 32;
	memset(pkt, 0, n);
	pkt[0] = 0x45; pkt[3] = (uint8_t)n; pkt[8] = 64; pkt[9] = 1;
	memcpy(pkt + 12, &src, 4); memcpy(pkt + 16, &dst, 4);
	uint16_t c = csum(pkt, 20); pkt[10] = c >> 8; pkt[11] = (uint8_t)c;
	uint8_t *i = pkt + 20;
	i[0] = 8; i[4] = 0x7e; i[5] = 0x57; i[6] = seq >> 8; i[7] = (uint8_t)seq;
	for (int k = 0; k < 32; k++) i[8 + k] = (uint8_t)('a' + k % 26);
	c = csum(i, 40); i[2] = c >> 8; i[3] = (uint8_t)c;
	return n;
}

static tls_conn conn;
static uint8_t rx[8192], out[2048];
static size_t rx_len;

static int send_dgram(const uint8_t *d, size_t n)
{
	return tls_write(&conn, out, ws_frame(out, 2, d, n));
}

/* next binary frame payload into d; answers pings; -1 on error/timeout */
static long recv_dgram(uint8_t *d, size_t cap)
{
	for (;;) {
		int op;
		size_t off, pl;
		long t = ws_parse(rx, rx_len, sizeof rx, &op, &off, &pl);
		if (t < 0) return -1;
		if (t > 0) {
			long r = -2;
			if (op == 2 && pl <= cap) { memcpy(d, rx + off, pl); r = (long)pl; }
			if (op == 9) tls_write(&conn, out, ws_frame(out, 0xA, rx + off, pl));
			if (op == 8) return -1;
			rx_len -= (size_t)t;
			memmove(rx, rx + t, rx_len);
			if (r >= 0) return r;
			continue;
		}
		long r = tls_read(&conn, rx + rx_len, sizeof rx - rx_len);
		if (r < 0) return -1;
		rx_len += (size_t)r;
	}
}

int main(int argc, char **argv)
{
	if (argc != 10) { fprintf(stderr, "usage: see source\n"); return 2; }
	uint8_t priv[32], peer[32], skey[32], ip[4];
	if (b64dec(priv, argv[1]) || b64dec(peer, argv[2]) || unhex32(skey, argv[6])) { fprintf(stderr, "bad key\n"); return 2; }
	uint32_t src, dst;
	inet_pton(AF_INET, argv[8], &src);
	inet_pton(AF_INET, argv[9], &dst);

	if (dns_resolve(argv[3], ip)) { puts("FAIL: dns"); return 1; }
	struct sockaddr_in srv;
	addr4(&srv, ip, 443);
	int fd = tcp_open(&srv, 15);
	if (fd < 0) { puts("FAIL: tcp"); return 1; }
	const char *err = tls_handshake(&conn, fd, argv[5], 0, 0, skey, x_now() + 30);
	if (err) { printf("FAIL: tls: %s\n", err); return 1; }
	puts("TLS 1.3 OK (pinned by Ed25519 key)");

	static char req[768], claims[160];
	snprintf(claims, sizeof claims, "\",\"p\":{\"Udp\":{\"timeout\":null}},\"r\":\"127.0.0.1\",\"rp\":%d}", atoi(argv[7]));
	long n = ws_request(req, sizeof req, argv[4], argv[5], claims);
	if (n < 0 || tls_write(&conn, (const uint8_t *)req, (size_t)n)) { puts("FAIL: upgrade write"); return 1; }
	size_t end = 0;
	while (!end) {
		long r = tls_read(&conn, rx + rx_len, sizeof rx - rx_len);
		if (r < 0) { puts("FAIL: upgrade read"); return 1; }
		rx_len += (size_t)r;
		for (size_t i = 0; i + 4 <= rx_len && !end; i++)
			if (!memcmp(rx + i, "\r\n\r\n", 4)) end = i + 4;
	}
	if (memcmp(rx, "HTTP/1.1 101", 12)) { printf("FAIL: upgrade refused: %.40s\n", rx); return 1; }
	if (getenv("UPGRADE_HDR")) printf("%.*s", (int)end, rx); /* UPGRADE_HDR: show response headers */
	rx_len -= end;
	memmove(rx, rx + end, rx_len);
	puts("WebSocket upgrade OK");

	static wg_state s;
	wg_init(&s, priv, peer, 0);
	uint8_t buf[2048], pkt[1500], rnd[32], ts[12];
	uint32_t index;
	struct timespec now;
	getrandom(rnd, 32, 0);
	getrandom(&index, 4, 0);
	clock_gettime(CLOCK_REALTIME, &now);
	wg_tai64n(ts, (uint64_t)now.tv_sec, (uint32_t)now.tv_nsec);
	wg_make_initiation(&s, buf, rnd, index, ts);
	if (send_dgram(buf, WG_INIT_LEN)) { puts("FAIL: send init"); return 1; }
	long m = recv_dgram(buf, sizeof buf);
	if (m < 0 || wg_consume_response(&s, buf, (size_t)m)) { printf("FAIL: handshake (%ld bytes)\n", m); return 1; }
	puts("WireGuard handshake OK over WSS");

	int ok = 0;
	for (uint16_t seq = 1; seq <= 3; seq++) {
		size_t len = icmp_echo(pkt, src, dst, seq);
		size_t c = wg_encrypt(&s, pkt, len, buf);
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		send_dgram(buf, c);
		for (;;) {
			m = recv_dgram(buf, sizeof buf);
			if (m < 0) { printf("seq %u: no reply\n", seq); break; }
			long p = wg_decrypt(&s, buf, (size_t)m, pkt);
			if (p <= 0) continue;
			clock_gettime(CLOCK_MONOTONIC, &t1);
			const uint8_t *ic = pkt + (pkt[0] & 15) * 4;
			if (pkt[9] == 1 && ic[0] == 0 && (ic[6] << 8 | ic[7]) == seq) {
				printf("seq %u: echo reply from %u.%u.%u.%u in %.1f ms\n", seq, pkt[12], pkt[13], pkt[14], pkt[15],
				       (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
				ok++;
				break;
			}
		}
	}
	printf(ok ? "PASS: %d/3 replies through WireGuard over WSS\n" : "FAIL: no replies\n", ok);
	return ok ? 0 : 1;
}
