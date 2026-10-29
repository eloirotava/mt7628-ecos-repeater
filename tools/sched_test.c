/* Host test for the network schedule (init/sched.c).
 * Built by tools/test_wifi_ui.py with -DSCHED_HOST_TEST. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../ra305x_ap_adv/ra305x_router/init/sched.c"

int main(void)
{
	int f, t;
	assert(!sched_parse("08:00-22:30", &f, &t) && f == 480 && t == 1350);
	assert(!sched_parse("22:00-06:00", &f, &t) && f == 1320 && t == 360);
	assert(!sched_parse("00:00-24:00", &f, &t) && f == 0 && t == 1440);
	assert(sched_parse("8:00-22:00", &f, &t) && sched_parse("08:00-25:00", &f, &t) && sched_parse("08:60-09:00", &f, &t));
	assert(sched_parse("08:00-24:30", &f, &t) && sched_parse("08:00-22:00x", &f, &t) && sched_parse("", &f, &t));
	/* inside, edges, crossing midnight, whole day */
	assert(sched_on(480, 480, 1350) && !sched_on(1350, 480, 1350) && !sched_on(479, 480, 1350));
	assert(sched_on(1400, 1320, 360) && sched_on(100, 1320, 360) && !sched_on(720, 1320, 360));
	assert(sched_on(5, 600, 600));
	/* local minute: UTC 12:00 at -180 is 09:00; negative wrap */
	assert(sched_minute(12 * 3600L, -180) == 9 * 60);
	assert(sched_minute(60L, -180) == 1440 - 180 + 1);
	assert(sched_minute(23 * 3600L, 120) == 60);
	puts("PASS: network schedule (format, windows across midnight, local time)");
	return 0;
}
