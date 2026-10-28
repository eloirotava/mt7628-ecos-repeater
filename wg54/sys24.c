/* Functions the compiler may call without a libc (from ntun's sys_nolibc.c).
 * Nothing from libgcc is linked: Debian's is built for MIPS32r2 with PIC,
 * and the BCM5354 is MIPS32r1. */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;
	while (n--) *a++ = *b++;
	return d;
}

void *memmove(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;
	if (a < b) while (n--) *a++ = *b++;
	else while (n--) a[n] = b[n];
	return d;
}

void *memset(void *d, int c, size_t n)
{
	unsigned char *a = d;
	while (n--) *a++ = (unsigned char)c;
	return d;
}

int memcmp(const void *x, const void *y, size_t n)
{
	const unsigned char *a = x, *b = y;
	for (; n; n--, a++, b++) if (*a != *b) return *a - *b;
	return 0;
}

/* 64-bit shifts gcc calls on 32-bit MIPS; only 32-bit shifts in here */
typedef unsigned long long u64;
typedef long long i64;

static u64 join(uint32_t hi, uint32_t lo) { return (u64)hi << 32 | lo; }

u64 __lshrdi3(u64 a, int b)
{
	uint32_t lo = (uint32_t)a, hi = (uint32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return join(0, hi >> (b - 32));
	return join(hi >> b, lo >> b | hi << (32 - b));
}

u64 __ashldi3(u64 a, int b)
{
	uint32_t lo = (uint32_t)a, hi = (uint32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return join(lo << (b - 32), 0);
	return join(hi << b | lo >> (32 - b), lo << b);
}

i64 __ashrdi3(i64 a, int b)
{
	uint32_t lo = (uint32_t)a;
	int32_t hi = (int32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return (i64)join((uint32_t)(hi >> 31), (uint32_t)(hi >> (b - 32)));
	return (i64)join((uint32_t)(hi >> b), lo >> b | (uint32_t)hi << (32 - b));
}
