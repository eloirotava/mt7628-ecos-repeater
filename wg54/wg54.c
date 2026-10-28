/* wg54: WireGuard client for Linux 2.4 routers without tun (BCM5354:
 * WRT54G v8 / WRT54GS v7 with DD-WRT micro). One peer, initiator only;
 * handshake and transport from ../ra305x_ap_adv/ra305x_router/wg/wg_proto.c.
 *
 *   wg54 genkey                 private key (base64) on stdout
 *   wg54 pubkey KEYFILE         public key of the private key in KEYFILE
 *   wg54 selftest
 *   wg54 run KEYFILE PEERPUB ENDPOINT-IP PORT IFNAME [KEEPALIVE [NTP-IP]]
 *
 * An IPIP device stands in for the tun interface (wg54.sh sets it up):
 *   ip tunnel add wg0 mode ipip local 127.0.0.1 remote 127.0.0.2
 * Packets routed to it are read before encapsulation by a packet socket
 * bound to it (outgoing direction only); the encapsulated copy
 * (127.0.0.1 -> 127.0.0.2) dies in the fallback tunl0, which has no
 * address, and the firewall drops it as well. Decrypted packets go back
 * wrapped as IPIP 127.0.0.2 -> 127.0.0.1, which the kernel decapsulates as
 * received on the device.
 *
 * No libc (static, system calls in mips24.S): current C libraries need a
 * 2.6 kernel. Only system calls that Linux 2.4 has are used. */
#include <stddef.h>
#include <stdint.h>
#include <asm/unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <fcntl.h>
#include "wg_proto.h"
#include "c25519.h"
#include "aead.h"

long raw_syscall(long n, long a, long b, long c, long d, long e, long f);
#define SC3(n, a, b, c) raw_syscall(__NR_##n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define SC6(n, a, b, c, d, e, f) \
	raw_syscall(__NR_##n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

#define REKEY_AFTER     120  /* s: start a new handshake */
#define REJECT_AFTER    180  /* s: stop using a session */
#define REKEY_TIMEOUT   5    /* s: retry an unanswered initiation */
#define CLOCK_SANE      1700000000L /* 2023-11: older means the clock was never set */
#define MTU_MAX         1600

/* ------------------------------------------------------------ small libc */

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) a++, b++;
	return *a == *b;
}

static void put(int fd, const char *s) { SC3(write, fd, s, slen(s)); }

static void say(const char *a, const char *b)
{
	put(2, "wg54: ");
	put(2, a);
	if (b) put(2, b);
	put(2, "\n");
}

static unsigned long atou(const char *s)
{
	unsigned long v = 0;
	while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned long)(*s++ - '0');
	return v;
}

static int parse_ip(const char *s, uint8_t ip[4])
{
	int i;
	for (i = 0; i < 4; i++) {
		unsigned long v = 0;
		int d = 0;
		while (*s >= '0' && *s <= '9' && d < 4) v = v * 10 + (unsigned long)(*s++ - '0'), d++;
		if (!d || v > 255) return -1;
		ip[i] = (uint8_t)v;
		if (i < 3 && *s++ != '.') return -1;
	}
	return *s ? -1 : 0;
}

static uint16_t be16(uint16_t v) { return (uint16_t)(v >> 8 | v << 8); }

static void addr4(struct sockaddr_in *a, const uint8_t ip[4], unsigned port)
{
	memset(a, 0, sizeof *a);
	a->sin_family = AF_INET;
	a->sin_port = be16((uint16_t)port);
	memcpy(&a->sin_addr, ip, 4);
}

/* ------------------------------------------------------------ base64 keys */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64val(char c)
{
	int i;
	for (i = 0; i < 64; i++) if (B64[i] == c) return i;
	return -1;
}

static int b64_decode32(uint8_t out[32], const char *s)
{
	unsigned long acc = 0;
	int bits = 0, n = 0, i;
	if (slen(s) != 44 || s[43] != '=') return -1;
	for (i = 0; i < 43; i++) {
		int v = b64val(s[i]);
		if (v < 0) return -1;
		acc = (acc << 6 | (unsigned long)v) & 0xffffff;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (n == 32) return -1;
			out[n++] = (uint8_t)(acc >> bits);
		}
	}
	return n == 32 ? 0 : -1;
}

static void b64_encode32(char out[45], const uint8_t in[32])
{
	int i, o = 0;
	unsigned long v;
	for (i = 0; i < 30; i += 3) {
		v = (unsigned long)in[i] << 16 | (unsigned long)in[i + 1] << 8 | in[i + 2];
		out[o++] = B64[v >> 18 & 63]; out[o++] = B64[v >> 12 & 63];
		out[o++] = B64[v >> 6 & 63];  out[o++] = B64[v & 63];
	}
	v = (unsigned long)in[30] << 16 | (unsigned long)in[31] << 8;
	out[o++] = B64[v >> 18 & 63]; out[o++] = B64[v >> 12 & 63];
	out[o++] = B64[v >> 6 & 63];  out[o++] = '=';
	out[o] = 0;
}

static int read_key(const char *path, uint8_t key[32])
{
	char b[80];
	long fd = SC3(open, path, O_RDONLY, 0), n;
	if (fd < 0) return -1;
	n = SC3(read, fd, b, sizeof b - 1);
	SC3(close, fd, 0, 0);
	if (n < 44) return -1;
	b[44] = 0;
	n = b64_decode32(key, b);
	wipe(b, sizeof b);
	return (int)n;
}

/* ------------------------------------------------------------ randomness, clock */

static long urandom = -1;

static int random_bytes(void *p, size_t n)
{
	uint8_t *b = p;
	if (urandom < 0) urandom = SC3(open, "/dev/urandom", O_RDONLY, 0);
	if (urandom < 0) return -1;
	while (n) {
		long r = SC3(read, urandom, b, n);
		if (r <= 0) return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

static long uptime(void)
{
	long si[32]; /* struct sysinfo: uptime is the first field */
	SC3(sysinfo, si, 0, 0);
	return si[0];
}

static long ntp_base = 0; /* unix time = ntp_base + uptime(), when the system clock is unset */

static void wall(long *sec, long *usec)
{
	long tv[2] = { 0, 0 };
	SC3(gettimeofday, tv, 0, 0);
	*sec = tv[0];
	*usec = tv[1];
	if (*sec < CLOCK_SANE && ntp_base) {
		*sec = ntp_base + uptime();
		*usec = 0;
	}
}

/* SNTP (RFC 4330): transmit timestamp of the reply */
static int sntp(const uint8_t ip[4])
{
	uint8_t pkt[48];
	struct sockaddr_in a;
	struct pollfd p;
	unsigned long secs;
	long fd = SC3(socket, AF_INET, SOCK_DGRAM, 0), n;
	if (fd < 0) return -1;
	addr4(&a, ip, 123);
	memset(pkt, 0, sizeof pkt);
	pkt[0] = 0x23; /* LI 0, version 4, client */
	SC6(sendto, fd, pkt, sizeof pkt, 0, &a, sizeof a);
	p.fd = (int)fd;
	p.events = POLLIN;
	n = SC3(poll, &p, 1, 3000) > 0 ? SC6(recvfrom, fd, pkt, sizeof pkt, 0, 0, 0) : -1;
	SC3(close, fd, 0, 0);
	if (n < 48 || (pkt[0] & 7) != 4) return -1;
	secs = (unsigned long)pkt[40] << 24 | (unsigned long)pkt[41] << 16 | (unsigned long)pkt[42] << 8 | pkt[43];
	if (secs - 2208988800UL < (unsigned long)CLOCK_SANE) return -1;
	ntp_base = (long)(secs - 2208988800UL) - uptime();
	return 0;
}

/* Strictly increasing TAI64N: the responder rejects older initiations */
static void timestamp(uint8_t out[12])
{
	static long last_s, last_us;
	long s, us;
	wall(&s, &us);
	if (s < last_s || (s == last_s && us <= last_us)) {
		s = last_s;
		us = last_us + 1;
		if (us >= 1000000) s++, us = 0;
	}
	last_s = s;
	last_us = us;
	wg_tai64n(out, (uint64_t)(unsigned long)s, (uint32_t)us * 1000u);
}

/* ------------------------------------------------------------ tunnel */

static wg_state wg;
static long udp = -1, pkt = -1, raw = -1;
static int ifindex;
static const char *ifname;
static struct sockaddr_in peer, loop1;
static long sess_time = -1, init_time = -1, last_tx;
static unsigned keepalive;
static int connected;
/* outgoing: packet read at txb + 16, encrypted in place */
static uint8_t txb[WG_DATA_HDR + MTU_MAX + 16 + WG_TAG];
/* incoming: datagram in rxb, plaintext after a 20-byte IPIP header in inj */
static uint8_t rxb[WG_DATA_HDR + MTU_MAX + 16 + WG_TAG], inj[20 + MTU_MAX + 16];

static void send_udp(const uint8_t *b, size_t n)
{
	SC6(sendto, udp, b, n, 0, &peer, sizeof peer);
	last_tx = uptime();
}

static void send_keepalive(void) { send_udp(txb, wg_encrypt(&wg, txb + WG_DATA_HDR, 0, txb)); }

static void send_initiation(long now)
{
	uint8_t rnd[32], ts[12], msg[WG_INIT_LEN];
	uint32_t index;
	if (random_bytes(rnd, sizeof rnd) || random_bytes(&index, sizeof index)) {
		say("no randomness (/dev/urandom)", 0);
		return;
	}
	timestamp(ts);
	wg_make_initiation(&wg, msg, rnd, index, ts);
	wipe(rnd, sizeof rnd);
	send_udp(msg, sizeof msg);
	init_time = now;
}

static int session_usable(long now)
{
	return wg.have_session && sess_time >= 0 && now - sess_time < REJECT_AFTER;
}

static int find_ifindex(void)
{
	struct ifreq r;
	memset(&r, 0, sizeof r);
	memcpy(r.ifr_name, ifname, slen(ifname) < IFNAMSIZ ? slen(ifname) : IFNAMSIZ - 1);
	if (SC3(ioctl, udp, SIOCGIFINDEX, &r) < 0) return -1;
	return r.ifr_ifindex;
}

static int bind_packet(int idx)
{
	struct sockaddr_ll a;
	if (pkt >= 0) SC3(close, pkt, 0, 0);
	pkt = SC3(socket, AF_PACKET, SOCK_DGRAM, be16(ETH_P_ALL));
	if (pkt < 0) return -1;
	memset(&a, 0, sizeof a);
	a.sll_family = AF_PACKET;
	a.sll_protocol = be16(ETH_P_ALL);
	a.sll_ifindex = idx;
	if (SC3(bind, pkt, &a, sizeof a) < 0) return -1;
	ifindex = idx;
	return 0;
}

/* plaintext at inj + 20, plen bytes (with WireGuard padding) */
static void inject(long plen)
{
	uint8_t *ip = inj + 20;
	unsigned tl;
	if (plen < 20 || ip[0] >> 4 != 4) return;
	tl = (unsigned)ip[2] << 8 | ip[3];
	if (tl < 20 || tl > (unsigned)plen) return;
	memset(inj, 0, 20);
	inj[0] = 0x45;
	inj[2] = (uint8_t)((tl + 20) >> 8);
	inj[3] = (uint8_t)(tl + 20);
	inj[8] = 64;
	inj[9] = 4; /* IPIP */
	inj[12] = 127; inj[15] = 2;   /* 127.0.0.2: the tunnel's remote end */
	inj[16] = 127; inj[19] = 1;   /* 127.0.0.1: its local end */
	SC6(sendto, raw, inj, tl + 20, 0, &loop1, sizeof loop1); /* the kernel fills id and checksum */
}

static void on_udp(long now)
{
	long n, p;
	int burst;
	for (burst = 0; burst < 32; burst++) {
		n = SC6(recvfrom, udp, rxb, sizeof rxb, MSG_DONTWAIT, 0, 0);
		if (n <= 0) return;
		switch (wg_msg_type(rxb, (size_t)n)) {
		case 2:
			if (!wg_consume_response(&wg, rxb, (size_t)n)) {
				sess_time = now;
				init_time = -1;
				if (!connected) say("connected", 0);
				connected = 1;
				send_keepalive(); /* confirms the session to the responder */
			}
			break;
		case 4:
			p = wg_decrypt(&wg, rxb, (size_t)n, inj + 20);
			if (p > 0) inject(p);
			break;
		default:
			break; /* initiations and cookie replies are not handled */
		}
	}
}

static void on_packet(long now)
{
	struct sockaddr_ll from;
	socklen_t fl;
	long n;
	int burst;
	for (burst = 0; burst < 32; burst++) {
		fl = sizeof from;
		n = SC6(recvfrom, pkt, txb + WG_DATA_HDR, MTU_MAX, MSG_DONTWAIT, &from, &fl);
		if (n <= 0) return;
		/* our own injected packets show up as incoming: only outgoing ones go to the peer */
		if (from.sll_pkttype != PACKET_OUTGOING || n < 20 || !session_usable(now)) continue;
		send_udp(txb, wg_encrypt(&wg, txb + WG_DATA_HDR, (size_t)n, txb));
	}
}

static int run(char **a, int n)
{
	static const uint8_t ntp_default[2][4] = { { 162, 159, 200, 1 }, { 162, 159, 200, 123 } };
	uint8_t key[32], peer_pub[32], ip[4], ntp_ip[4], lo1[4] = { 127, 0, 0, 1 };
	struct pollfd pf[2];
	unsigned long port;
	long s, us, last_check = 0;
	int tries, have_ntp_ip;

	if (n < 5) return 2;
	if (read_key(a[0], key)) { say("bad private key file ", a[0]); return 1; }
	if (b64_decode32(peer_pub, a[1])) { say("bad peer public key", 0); return 1; }
	port = atou(a[3]);
	if (parse_ip(a[2], ip) || port < 1 || port > 65535) { say("bad endpoint ", a[2]); return 1; }
	ifname = a[4];
	keepalive = n > 5 ? (unsigned)atou(a[5]) : 25;
	have_ntp_ip = n > 6 && !parse_ip(a[6], ntp_ip);

	wg_init(&wg, key, peer_pub, 0);
	wipe(key, sizeof key);
	addr4(&peer, ip, (unsigned)port);
	addr4(&loop1, lo1, 0);

	udp = SC3(socket, AF_INET, SOCK_DGRAM, 0);
	raw = SC3(socket, AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (udp < 0 || raw < 0) { say("cannot open sockets (root?)", 0); return 1; }
	if ((ifindex = find_ifindex()) < 0 || bind_packet(ifindex)) { say("no interface ", ifname); return 1; }

	/* the responder needs increasing timestamps: wait for a usable clock (about 1 min) */
	for (tries = 0; tries < 6; tries++) {
		wall(&s, &us);
		if (s >= CLOCK_SANE) break;
		if (!sntp(have_ntp_ip ? ntp_ip : ntp_default[tries & 1])) { say("clock from SNTP", 0); break; }
		SC3(poll, 0, 0, 10000);
	}
	if (tries == 6) say("warning: clock not set; the peer may reject the handshake", 0);
	say("started on ", ifname);

	for (;;) {
		long now;
		pf[0].fd = (int)udp; pf[0].events = POLLIN; pf[0].revents = 0;
		pf[1].fd = (int)pkt; pf[1].events = POLLIN; pf[1].revents = 0;
		SC3(poll, pf, 2, 1000);
		now = uptime();
		if (pf[0].revents) on_udp(now);
		if (pf[1].revents) on_packet(now);

		/* interface recreated (firewall or network restart): follow its new index */
		if (now - last_check >= 30) {
			int idx = find_ifindex();
			last_check = now;
			if (idx > 0 && idx != ifindex && !bind_packet(idx)) say("interface back: ", ifname);
		}
		if (!wg.have_session || now - sess_time >= REKEY_AFTER)
			if (init_time < 0 || now - init_time >= REKEY_TIMEOUT) send_initiation(now);
		if (connected && !session_usable(now)) {
			connected = 0;
			say("session expired; peer not answering", 0);
		}
		if (keepalive && session_usable(now) && now - last_tx >= (long)keepalive) send_keepalive();
	}
}

/* ------------------------------------------------------------ commands */

static int hexeq(const uint8_t *b, const char *h, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		int hi = h[2 * i] <= '9' ? h[2 * i] - '0' : h[2 * i] - 'a' + 10;
		int lo = h[2 * i + 1] <= '9' ? h[2 * i + 1] - '0' : h[2 * i + 1] - 'a' + 10;
		if (b[i] != (uint8_t)(hi << 4 | lo)) return 0;
	}
	return 1;
}

static int selftest(void)
{
	uint8_t k[32], out[32], n[12], msg[40];
	int i;
	/* BLAKE2s keyed (blake2s-kat.txt): key 00..1f, empty input */
	for (i = 0; i < 32; i++) k[i] = (uint8_t)i;
	wg_blake2s_keyed(out, 32, k, 32, 0, 0);
	if (!hexeq(out, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49", 32)) {
		say("FAIL: keyed BLAKE2s", 0);
		return 1;
	}
	/* X25519 (RFC 7748 6.1): Alice's public key */
	for (i = 0; i < 32; i++) {
		static const char a[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
		int hi = a[2 * i] <= '9' ? a[2 * i] - '0' : a[2 * i] - 'a' + 10;
		int lo = a[2 * i + 1] <= '9' ? a[2 * i + 1] - '0' : a[2 * i + 1] - 'a' + 10;
		k[i] = (uint8_t)(hi << 4 | lo);
	}
	x25519_base(out, k);
	if (!hexeq(out, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32)) {
		say("FAIL: X25519", 0);
		return 1;
	}
	/* ChaCha20-Poly1305 round trip and tamper detection */
	memset(n, 7, sizeof n);
	memset(msg, 'x', 24);
	aead_seal(msg, k, n, out, 32, msg, 24);
	if (aead_open(msg, k, n, out, 32, msg, 40) || msg[0] != 'x' || msg[23] != 'x') {
		say("FAIL: ChaCha20-Poly1305", 0);
		return 1;
	}
	aead_seal(msg, k, n, out, 32, msg, 24);
	msg[3] ^= 1;
	if (!aead_open(msg, k, n, out, 32, msg, 40)) { say("FAIL: AEAD accepted a forgery", 0); return 1; }
	say("selftest PASS", 0);
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t key[32], pub[32];
	char b[45];

	if (argc >= 2 && streq(argv[1], "genkey")) {
		if (random_bytes(key, 32)) return 1;
		key[0] &= 248;
		key[31] = (key[31] & 127) | 64;
		b64_encode32(b, key);
		put(1, b);
		put(1, "\n");
		return 0;
	}
	if (argc == 3 && streq(argv[1], "pubkey")) {
		if (read_key(argv[2], key)) { say("bad private key file ", argv[2]); return 1; }
		x25519_base(pub, key);
		wipe(key, sizeof key);
		b64_encode32(b, pub);
		put(1, b);
		put(1, "\n");
		return 0;
	}
	if (argc == 2 && streq(argv[1], "selftest")) return selftest();
	if (argc >= 7 && streq(argv[1], "run")) {
		int r = run(argv + 2, argc - 2);
		if (r != 2) return r;
	}
	put(2, "usage: wg54 genkey | pubkey KEYFILE | selftest\n"
	       "       wg54 run KEYFILE PEERPUB ENDPOINT-IP PORT IFNAME [KEEPALIVE [NTP-IP]]\n");
	return 2;
}
