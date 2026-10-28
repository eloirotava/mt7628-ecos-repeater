/* Host test for ra305x_router/wg/wg_proto.c against a real WireGuard peer.
 *   wg_host_test <our-private-b64> <peer-public-b64> <peer-ip> <port> <tunnel-src-ip> <ping-dst-ip>
 *   wg_host_test --selftest
 * Sends a handshake initiation, then ICMP echo requests through the tunnel and
 * prints the decrypted replies. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "wg_proto.h"

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
		if (bits >= 8) {
			bits -= 8;
			if (n == 32) return -1;
			out[n++] = (uint8_t)(acc >> bits);
		}
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
	pkt[0] = 0x45; pkt[2] = n >> 8; pkt[3] = (uint8_t)n; pkt[8] = 64; pkt[9] = 1;
	memcpy(pkt + 12, &src, 4); memcpy(pkt + 16, &dst, 4);
	uint16_t c = csum(pkt, 20); pkt[10] = c >> 8; pkt[11] = (uint8_t)c;
	uint8_t *i = pkt + 20;
	i[0] = 8; i[4] = 0x7e; i[5] = 0x57; i[6] = seq >> 8; i[7] = (uint8_t)seq;
	for (int k = 0; k < 32; k++) i[8 + k] = (uint8_t)('a' + k % 26);
	c = csum(i, 8 + 32); i[2] = c >> 8; i[3] = (uint8_t)c;
	return n;
}

static int selftest(void)
{
	/* BLAKE2s keyed KAT (blake2s-kat.txt): key 00..1f, empty input */
	static const uint8_t want[32] = {
		0x48,0xa8,0x99,0x7d,0xa4,0x07,0x87,0x6b,0x3d,0x79,0xc0,0xd9,0x23,0x25,0xad,0x3b,
		0x89,0xcb,0xb7,0x54,0xd8,0x6a,0xb7,0x1a,0xee,0x04,0x7a,0xd3,0x45,0xfd,0x2c,0x49 };
	uint8_t key[32], out[32];
	for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
	wg_blake2s_keyed(out, 32, key, 32, 0, 0);
	if (memcmp(out, want, 32)) { puts("FAIL: keyed BLAKE2s KAT"); return 1; }
	/* TAI64N layout */
	uint8_t t[12];
	wg_tai64n(t, 0, 1);
	if (t[0] != 0x40 || t[7] != 0x0a || t[11] != 1) { puts("FAIL: TAI64N"); return 1; }
	puts("PASS: keyed BLAKE2s KAT and TAI64N");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
	if (argc != 7) { fprintf(stderr, "usage: see source\n"); return 2; }
	uint8_t priv[32], peer[32];
	if (b64dec(priv, argv[1]) || b64dec(peer, argv[2])) { fprintf(stderr, "bad key\n"); return 2; }
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[4])) };
	inet_pton(AF_INET, argv[3], &to.sin_addr);
	uint32_t src, dst;
	inet_pton(AF_INET, argv[5], &src);
	inet_pton(AF_INET, argv[6], &dst);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct timeval tv = { 2, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

	static wg_state s;
	wg_init(&s, priv, peer, 0);
	uint8_t buf[2048], pkt[1500], rnd[32];
	uint32_t index;
	struct timespec now;
	for (int attempt = 0; attempt < 3 && !s.have_session; attempt++) {
		getrandom(rnd, 32, 0);
		getrandom(&index, 4, 0);
		clock_gettime(CLOCK_REALTIME, &now);
		uint8_t ts[12];
		wg_tai64n(ts, (uint64_t)now.tv_sec, (uint32_t)now.tv_nsec);
		wg_make_initiation(&s, buf, rnd, index, ts);
		sendto(fd, buf, WG_INIT_LEN, 0, (struct sockaddr *)&to, sizeof to);
		printf("initiation sent (index %08x)\n", index);
		ssize_t n = recv(fd, buf, sizeof buf, 0);
		if (n < 0) { printf("no response (%s)\n", strerror(errno)); continue; }
		printf("received %zd bytes, type %d\n", n, wg_msg_type(buf, (size_t)n));
		if (wg_consume_response(&s, buf, (size_t)n)) printf("response rejected\n");
	}
	if (!s.have_session) { puts("FAIL: no session"); return 1; }
	puts("handshake OK: session keys derived");

	int ok = 0;
	for (uint16_t seq = 1; seq <= 3; seq++) {
		size_t len = icmp_echo(pkt, src, dst, seq);
		size_t m = wg_encrypt(&s, pkt, len, buf);
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		sendto(fd, buf, m, 0, (struct sockaddr *)&to, sizeof to);
		for (;;) {
			ssize_t n = recv(fd, buf, sizeof buf, 0);
			if (n < 0) { printf("seq %u: timeout\n", seq); break; }
			long p = wg_decrypt(&s, buf, (size_t)n, pkt);
			if (p < 0) { printf("seq %u: undecryptable datagram (%zd bytes)\n", seq, n); continue; }
			if (p == 0) { printf("keepalive\n"); continue; }
			clock_gettime(CLOCK_MONOTONIC, &t1);
			const uint8_t *ic = pkt + (pkt[0] & 15) * 4;
			if (pkt[9] == 1 && ic[0] == 0 && (ic[6] << 8 | ic[7]) == seq) {
				printf("seq %u: echo reply from %u.%u.%u.%u in %.1f ms\n", seq, pkt[12], pkt[13], pkt[14], pkt[15],
				       (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
				ok++;
				break;
			}
			printf("seq %u: other packet (%ld bytes, proto %u)\n", seq, p, pkt[9]);
		}
	}
	printf(ok ? "PASS: %d/3 replies through the tunnel\n" : "FAIL: no replies\n", ok);
	return ok ? 0 : 1;
}
