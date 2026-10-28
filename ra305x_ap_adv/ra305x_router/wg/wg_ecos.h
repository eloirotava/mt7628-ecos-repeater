/* WireGuard client inside the MT7628KN extender firmware. */
#ifndef WG_ECOS_H
#define WG_ECOS_H

#include <cyg/kernel/kapi.h>

/* wg_if.c */
void wg_if_attach(cyg_sem_t *wake);
int wg_if_dequeue(unsigned char *buf, int max);
void wg_if_flush(void);
void wg_if_input(unsigned char *buf, int len);
void wg_if_counters(unsigned long *rx_bytes, unsigned long *tx_bytes);

/* wg_ecos.c: for init and the web interface */
enum { WG_OFF, WG_STARTING, WG_CLOCK, WG_HANDSHAKE, WG_CONNECTED, WG_ERROR };
void wg_ecos_start(void);
int wg_ecos_state(void);
const char *wg_ecos_status(void);
int wg_ecos_public_key(char b64[45]);   /* 0 when the device key exists */
long wg_ecos_handshake_age(void);       /* seconds since the last handshake, -1 if none */
void wg_ecos_counters(unsigned long *rx, unsigned long *tx);

/* base64 of 32-byte keys (WireGuard format); also used by the web interface */
int wg_b64_decode32(unsigned char out[32], const char *s);
void wg_b64_encode32(char out[45], const unsigned char in[32]);

#endif
