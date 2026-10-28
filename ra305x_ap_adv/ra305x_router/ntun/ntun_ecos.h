/* ntun client inside the MT7628KN extender firmware. */
#ifndef NTUN_ECOS_H
#define NTUN_ECOS_H

#include <stddef.h>

#define NTUN_VFD_BASE 0x4000 /* virtual file descriptors, above any socket */

/* sys_ecos.c */
void ntun_entropy_add(const void *d, size_t n);
void ntun_entropy_collect(void);

/* ntun_ecos.c */
long ntun_vfile_open(const char *path);
long ntun_vfile_read(int fd, void *b, size_t n);
void ntun_ecos_log(const char *m);
void ntun_ecos_linked(void);

/* For the web interface and init */
enum { NTUN_OFF, NTUN_STARTING, NTUN_CONNECTING, NTUN_CONNECTED, NTUN_ERROR };
void ntun_ecos_start(void);
int ntun_ecos_state(void);
const char *ntun_ecos_status(void);
unsigned ntun_ecos_status_age(void);   /* seconds since the last status change */
int ntun_ecos_public_key(char hex[65]); /* 0 when the device key exists */

#endif
