/* sys.h on eCos (MT7628KN extender firmware): BSD sockets, poll() over
 * select(), a virtual resolv.conf with the DHCP DNS server, and an entropy
 * pool for x_getrandom. Returns >= 0 on success, -errno on error. */
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <sys/select.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <cfg_dns.h>
#include "sys.h"
#include "blake2s.h"
#include "crypto_ecos.h"

static long vfile_read(void *b, size_t n);

/* The call is evaluated exactly once: as a macro that used its argument
 * twice, every socket(), connect() and write() ran twice (two sockets per
 * socket() call leaked descriptors, each TLS record went out twice). */
static long ret(long r)
{
	return r < 0 ? -(long)(errno ? errno : EIO) : r;
}
#define RET(r) ret((long)(r))

long x_socket(int domain, int type, int proto)
{
	return RET(socket(domain, type, proto));
}

long x_connect(int fd, const struct sockaddr_in *a)
{
	struct sockaddr_in s = *a;
	s.sin_len = sizeof s;
	return RET(connect(fd, (struct sockaddr *)&s, sizeof s));
}

long x_setsockopt(int fd, int level, int opt, const void *v, unsigned len)
{
	/* SO_SNDTIMEO/SO_RCVTIMEO: struct timeval on this stack too */
	return RET(setsockopt(fd, level, opt, v, len));
}

long x_poll(struct pollfd *fds, unsigned n, int ms)
{
	fd_set rd, wr;
	struct timeval tv, *tp = 0;
	unsigned i;
	int max = -1, r, ready = 0;

	FD_ZERO(&rd);
	FD_ZERO(&wr);
	for (i = 0; i < n; i++) {
		fds[i].revents = 0;
		if (fds[i].fd < 0) continue;
		if (fds[i].events & POLLIN) FD_SET(fds[i].fd, &rd);
		if (fds[i].events & POLLOUT) FD_SET(fds[i].fd, &wr);
		if (fds[i].fd > max) max = fds[i].fd;
	}
	if (ms >= 0) {
		tv.tv_sec = ms / 1000;
		tv.tv_usec = (ms % 1000) * 1000;
		tp = &tv;
	}
	r = select(max + 1, &rd, &wr, 0, tp);
	if (r < 0) return -(long)(errno ? errno : EIO);
	for (i = 0; i < n; i++) {
		if (fds[i].fd < 0) continue;
		/* EOF and errors show up as readable; read() then returns 0 or -1 */
		if (FD_ISSET(fds[i].fd, &rd)) fds[i].revents |= POLLIN;
		if (FD_ISSET(fds[i].fd, &wr)) fds[i].revents |= POLLOUT;
		if (fds[i].revents) ready++;
	}
	return ready;
}

long x_read(int fd, void *b, size_t n)
{
	if (fd >= CRYPTO_VFD_BASE) return vfile_read(b, n);
	return RET(read(fd, b, n));
}

long x_write(int fd, const void *b, size_t n)
{
	return RET(write(fd, b, n));
}

long x_sendto(int fd, const void *b, size_t n, const struct sockaddr_in *a)
{
	struct sockaddr_in s = *a;
	s.sin_len = sizeof s;
	return RET(sendto(fd, b, n, 0, (struct sockaddr *)&s, sizeof s));
}

long x_recv(int fd, void *b, size_t n, int flags)
{
	return RET(recv(fd, b, n, flags));
}

long x_recvfrom(int fd, void *b, size_t n, int flags, struct sockaddr_in *from)
{
	socklen_t len = sizeof *from;
	return RET(recvfrom(fd, b, n, flags, (struct sockaddr *)from, &len));
}

long x_bind(int fd, const struct sockaddr_in *a)
{
	struct sockaddr_in s = *a;
	s.sin_len = sizeof s;
	return RET(bind(fd, (struct sockaddr *)&s, sizeof s));
}

long x_close(int fd)
{
	if (fd >= CRYPTO_VFD_BASE) return 0;
	return RET(close(fd));
}

/* Only /etc/resolv.conf exists: the DNS server from the upstream DHCP,
 * re-read on every lookup. One reader at a time (dns_resolve). */
static char resolv[40];
static size_t resolv_off;

long x_open(const char *path)
{
	struct in_addr a;
	if (strcmp(path, "/etc/resolv.conf")) return -ENOENT;
	a.s_addr = DNS_group_get(0);
	if (!a.s_addr) return -ENOENT;
	snprintf(resolv, sizeof resolv, "nameserver %s\n", inet_ntoa(a));
	resolv_off = 0;
	return CRYPTO_VFD_BASE;
}

static long vfile_read(void *b, size_t n)
{
	size_t len = strlen(resolv);
	if (resolv_off >= len) return 0;
	if (n > len - resolv_off) n = len - resolv_off;
	memcpy(b, resolv + resolv_off, n);
	resolv_off += n;
	return (long)n;
}

long x_now(void)
{
	return (long)(cyg_current_time() / 100);
}

void x_sleep(unsigned s)
{
	cyg_thread_delay((cyg_tick_count_t)s * 100);
}

void x_log(const char *m)
{
	diag_printf("%s\n", m);
}

/* ---------------------------------------------------------------- entropy
 * No hardware RNG is documented for the MT7628KN. The pool hashes:
 * CP0 Count (CPU cycle counter) sampled across timer interrupts, the
 * seed saved in flash (renewed every boot), MAC, uptime and network
 * timing. Output: BLAKE2s(key || counter || Count), and the key is
 * ratcheted after every call so earlier output cannot be recomputed. */

static blake2s_ctx pool;
static uint8_t pool_key[32];
static uint32_t pool_ctr;
static int pool_ready;

static inline uint32_t cp0_count(void)
{
	uint32_t c;
	__asm__ __volatile__("mfc0 %0, $9" : "=r"(c));
	return c;
}

void crypto_entropy_add(const void *d, size_t n)
{
	uint32_t c = cp0_count();
	if (!pool_ready && pool_ctr == 0) {
		blake2s_init(&pool);
		pool_ctr = 1;
	}
	blake2s_update(&pool, (const uint8_t *)&c, sizeof c);
	blake2s_update(&pool, (const uint8_t *)d, n);
}

/* Blocks for about 5 s: call from a worker thread, never from httpd. */
void crypto_entropy_collect(void)
{
	uint32_t s[64];
	int i, j;

	for (j = 0; j < 8; j++) {
		for (i = 0; i < 64; i++) {
			s[i] = cp0_count();
			/* Wake on the next tick: the cycle count at wakeup varies
			 * with interrupt and scheduling latency. */
			cyg_thread_delay(1);
		}
		crypto_entropy_add(s, sizeof s);
	}
	{
		cyg_tick_count_t t = cyg_current_time();
		crypto_entropy_add(&t, sizeof t);
	}
	blake2s_final(&pool, pool_key);
	pool_ready = 1;
}

int crypto_entropy_ready(void)
{
	return pool_ready;
}

long x_getrandom(void *b, size_t n)
{
	uint8_t *o = b, blk[32];
	size_t done = 0, k;
	blake2s_ctx x;
	uint32_t c;

	if (!pool_ready) return -EAGAIN;
	while (done < n) {
		c = cp0_count();
		blake2s_init(&x);
		blake2s_update(&x, pool_key, 32);
		blake2s_update(&x, (const uint8_t *)&pool_ctr, sizeof pool_ctr);
		blake2s_update(&x, (const uint8_t *)&c, sizeof c);
		blake2s_final(&x, blk);
		pool_ctr++;
		k = n - done < 32 ? n - done : 32;
		memcpy(o + done, blk, k);
		done += k;
	}
	/* ratchet */
	blake2s_init(&x);
	blake2s_update(&x, pool_key, 32);
	blake2s_update(&x, (const uint8_t *)"ratchet", 7);
	blake2s_final(&x, pool_key);
	memset(blk, 0, sizeof blk);
	return (long)n;
}
