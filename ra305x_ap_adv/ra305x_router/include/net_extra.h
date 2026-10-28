/* Extra Wi-Fi networks (init/net_extra.c) */
#ifndef NET_EXTRA_H
#define NET_EXTRA_H

#define NET_EXTRA_MAX 3 /* networks 2..4 on ra1..ra3 */

int net_extra_parse(const char *s, unsigned long *ip, unsigned long *mask);
int net_extra_routed(int n, unsigned long *ip, unsigned long *mask);
int net_extra_ifnames(char names[][8], int max);
void net_extra_apply(void);
void net_extra_fw_rules(void (*set)(char *));

#endif
