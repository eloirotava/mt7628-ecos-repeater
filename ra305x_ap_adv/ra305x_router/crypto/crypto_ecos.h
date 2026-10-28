/* Shared crypto and system layer for the firmware's network clients
 * (WireGuard, wstunnel transport). Sources from github.com/eloirotava/ntun. */
#ifndef CRYPTO_ECOS_H
#define CRYPTO_ECOS_H

#include <stddef.h>

#define CRYPTO_VFD_BASE 0x4000 /* virtual file descriptors, above any socket */

/* Entropy pool (sys_ecos.c). collect() blocks ~5 s: call from a worker
 * thread at boot; x_getrandom() returns -EAGAIN until it has run. */
void crypto_entropy_add(const void *d, size_t n);
void crypto_entropy_collect(void);
int crypto_entropy_ready(void);

#endif
