/* Extra Wi-Fi networks (init/net_extra.c) */
#ifndef NET_EXTRA_H
#define NET_EXTRA_H

#define NET_EXTRA_MAX 7 /* networks 1..7 on ra0..ra6 (1 only in bridge-based setups) */

int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask);
int net_extra_routed(int n, unsigned long *ip, unsigned long *mask);
int net_extra_ifnames(char names[][8], int max);
void net_extra_apply(void);
void net_extra_fw_rules(void (*set)(char *));
void net_extra_fw_ready(void);
void net_extra_fw_flushed(void);
int net_extra_via_wg(int n);
int net_extra_bridge_base(void);
void net_extra_lan_changed(void);

#endif
