/* Minimal WireGuard initiator (one peer): handshake and transport data.
 * Protocol: https://www.wireguard.com/protocol/ (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s).
 * Portable C without I/O; crypto from the ntun sources (blake2s, c25519, aead).
 * Not implemented: acting as responder, cookie replies (mac2 stays zero). */
#ifndef WG_PROTO_H
#define WG_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define WG_INIT_LEN     148
#define WG_RESP_LEN     92
#define WG_DATA_HDR     16
#define WG_TAG          16
#define WG_REPLAY_BITS  1024

typedef struct {
	/* configuration */
	uint8_t priv[32], pub[32], peer_pub[32], psk[32];
	/* handshake in progress */
	uint8_t e_priv[32], h[32], ck[32];
	uint32_t local_index;
	uint8_t last_init[WG_INIT_LEN];
	/* current session */
	int have_session;
	uint32_t peer_index;
	uint8_t send_key[32], recv_key[32];
	uint64_t send_counter, recv_max;
	uint32_t replay[WG_REPLAY_BITS / 32];
} wg_state;

/* priv: our private key; peer: responder public key; psk: may be NULL */
void wg_init(wg_state *s, const uint8_t priv[32], const uint8_t peer[32], const uint8_t psk[32]);

/* rnd: 32 random bytes for the ephemeral key; index: random local index;
 * tai64n: 12-byte timestamp, must increase between initiations. */
void wg_make_initiation(wg_state *s, uint8_t out[WG_INIT_LEN], const uint8_t rnd[32],
                        uint32_t index, const uint8_t tai64n[12]);

/* 0 on success (session established), -1 if the response is not ours or invalid */
int wg_consume_response(wg_state *s, const uint8_t *msg, size_t len);

/* Encrypts an IP packet; returns the datagram length (in+16+16, padded to 16). */
size_t wg_encrypt(wg_state *s, const uint8_t *in, size_t len, uint8_t *out);

/* Decrypts a transport datagram in place into out; returns plaintext length
 * (may include zero padding; 0 = keepalive), or -1. */
long wg_decrypt(wg_state *s, const uint8_t *msg, size_t len, uint8_t *out);

/* Message type of a received datagram (1..4) or 0 */
int wg_msg_type(const uint8_t *msg, size_t len);

/* TAI64N from UNIX seconds and nanoseconds */
void wg_tai64n(uint8_t out[12], uint64_t unix_secs, uint32_t nanos);

/* Keyed BLAKE2s (exposed for tests) */
void wg_blake2s_keyed(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
                      const uint8_t *in, size_t inlen);

#endif
