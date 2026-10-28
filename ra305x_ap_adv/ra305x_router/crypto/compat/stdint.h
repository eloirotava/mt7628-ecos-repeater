/* eCos toolchain has no <stdint.h>; the network stack already defines the
 * fixed-width types in sys/bsdtypes.h. Only used by the crypto and wg modules. */
#ifndef NTUN_COMPAT_STDINT_H
#define NTUN_COMPAT_STDINT_H
#include <cyg/infra/cyg_type.h>
#include <sys/bsdtypes.h>
#endif
