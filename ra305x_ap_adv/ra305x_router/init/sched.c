/* Network schedule: networks 2..7 can be on only inside a daily window,
 * SYS_NETn_SCHED = "HH:MM-HH:MM" in local time (SYS_TZ_OFFSET minutes from
 * UTC, default -180); the window may cross midnight; empty: always on.
 * Network 1 is the main BSS and always stays on.
 * Every 30 s the interface (ra1..ra6) is brought down or up; addresses and
 * DHCP of a routed network stay in place. Until the time is known (SNTP)
 * nothing is turned off: a wrong clock never takes a network down. */
#ifndef SCHED_HOST_TEST
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#endif
#include "sched.h"

/* "HH:MM-HH:MM" -> minutes of the day; 0 if valid */
int sched_parse(const char *s, int *from, int *to)
{
	int h1, m1, h2, m2;
	char tail;
	if (sscanf(s, "%2d:%2d-%2d:%2d%c", &h1, &m1, &h2, &m2, &tail) != 4) return -1;
	if (h1 < 0 || h1 > 23 || h2 < 0 || h2 > 24 || m1 < 0 || m1 > 59 || m2 < 0 || m2 > 59) return -1;
	if (h2 == 24 && m2) return -1;
	if (strlen(s) != 11) return -1;
	*from = h1 * 60 + m1;
	*to = h2 * 60 + m2;
	return 0;
}

/* is minute-of-day now inside [from, to)? from == to: the whole day */
int sched_on(int now, int from, int to)
{
	if (from == to) return 1;
	return from < to ? now >= from && now < to : now >= from || now < to;
}

/* local minute of the day for a UNIX time and an offset in minutes */
int sched_minute(long unix_time, int tz_minutes)
{
	long m = (unix_time / 60 + tz_minutes) % 1440;
	return (int)(m < 0 ? m + 1440 : m);
}

#ifndef SCHED_HOST_TEST
extern int CFG_get_str(int id, char *val);
extern cyg_bool_t netif_down(const char *intf);
extern cyg_bool_t netif_up(const char *intf);
extern long wg_ecos_unix_time(int sync);

static const int sched_ids[6] = { CFG_SYS_NET2_SCHED, CFG_SYS_NET3_SCHED, CFG_SYS_NET4_SCHED, CFG_SYS_NET5_SCHED, CFG_SYS_NET6_SCHED, CFG_SYS_NET7_SCHED };
static signed char off_now[6]; /* 1: turned off by the schedule */

/* 1: network n (2..7) is off because of its schedule */
int sched_is_off(int n) { return n >= 2 && n <= 7 ? off_now[n - 2] : 0; }

int sched_tz(void)
{
	char v[12];
	int tz;
	v[0] = 0;
	CFG_get_str(CFG_SYS_TZ_OFFSET, v);
	if (!v[0]) return -180;
	tz = atoi(v);
	return tz < -720 || tz > 840 ? -180 : tz;
}

static cyg_handle_t sched_handle;
static cyg_thread sched_obj;
static char sched_stack[3072];

static void sched_thread(cyg_addrword_t arg)
{
	int tries = 0;
	(void)arg;
	for (;;) {
		char v[24], bss[8], ifn[8];
		long t;
		int n, count, now, from, to, want;
		cyg_thread_delay(3000);
		/* ask SNTP at most every 10 minutes while the time is unknown */
		t = wg_ecos_unix_time(tries++ % 20 == 0);
		if (!t) continue;
		now = sched_minute(t, sched_tz());
		bss[0] = 0;
		CFG_get_str(CFG_WLN_BssidNum, bss);
		count = atoi(bss);
		for (n = 2; n <= 7; n++) {
			v[0] = 0;
			if (n <= count) CFG_get_str(sched_ids[n - 2], v);
			want = n > count || !v[0] || sched_parse(v, &from, &to) || sched_on(now, from, to);
			if (want == !off_now[n - 2]) continue;
			snprintf(ifn, sizeof ifn, "ra%d", n - 1);
			if (want) netif_up(ifn); else netif_down(ifn);
			off_now[n - 2] = (signed char)!want;
			diag_printf("sched: network %d %s (%02d:%02d local)\n", n, want ? "on" : "off by schedule", now / 60, now % 60);
		}
	}
}

void sched_start(void)
{
	cyg_thread_create(15, sched_thread, 0, "sched", sched_stack, sizeof sched_stack, &sched_handle, &sched_obj);
	cyg_thread_resume(sched_handle);
}
#endif
