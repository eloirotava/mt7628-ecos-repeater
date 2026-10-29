/* Network schedule (init/sched.c) */
#ifndef SCHED_H
#define SCHED_H

int sched_parse(const char *s, int *from, int *to);
int sched_on(int now, int from, int to);
int sched_minute(long unix_time, int tz_minutes);
int sched_is_off(int n);
int sched_tz(void);
void sched_start(void);

#endif
