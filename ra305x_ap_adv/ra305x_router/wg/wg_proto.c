/* Minimal WireGuard initiator; see wg_proto.h. Names follow the protocol
 * description: C (chaining key), H (hash), KDFn = HKDF with HMAC-BLAKE2s. */
#include <string.h>
#include "wg_proto.h"
#include "blake2s.h"
#include "c25519.h"
#include "aead.h"

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[] = "mac1----";

static void put32le(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static uint32_t get32le(const uint8_t *p) { return p[0] | p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static void put64le(uint8_t *p, uint64_t v) { int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint64_t get64le(const uint8_t *p) { uint64_t v = 0; int i; for (i = 7; i >= 0; i--) v = v << 8 | p[i]; return v; }

static void hash(uint8_t out[32], const void *a, size_t al, const void *b, size_t bl)
{
	blake2s_ctx x;
	blake2s_init(&x);
	blake2s_update(&x, a, al);
	if (bl) blake2s_update(&x, b, bl);
	blake2s_final(&x, out);
}

/* RFC 7693 parameter block word 0: digest length, key length, fanout, depth.
 * blake2s_init() sets it for 32 bytes, unkeyed; adjust and prepend the key block. */
void wg_blake2s_keyed(uint8_t *out, size_t outlen, const uint8_t *key, size_t keylen,
                      const uint8_t *in, size_t inlen)
{
	blake2s_ctx x;
	uint8_t block[64], full[32];
	blake2s_init(&x);
	x.h[0] ^= 32u ^ (uint32_t)outlen ^ ((uint32_t)keylen << 8);
	if (keylen) {
		memset(block, 0, sizeof block);
		memcpy(block, key, keylen);
		blake2s_update(&x, block, 64);
	}
	blake2s_update(&x, in, inlen);
	blake2s_final(&x, full);
	memcpy(out, full, outlen);
	wipe(block, sizeof block);
	wipe(full, sizeof full);
}

static void hmac(uint8_t out[32], const uint8_t key[32], const uint8_t *in, size_t len)
{
	uint8_t pad[64], inner[32];
	blake2s_ctx x;
	int i;
	for (i = 0; i < 64; i++) pad[i] = (i < 32 ? key[i] : 0) ^ 0x36;
	blake2s_init(&x);
	blake2s_update(&x, pad, 64);
	blake2s_update(&x, in, len);
	blake2s_final(&x, inner);
	for (i = 0; i < 64; i++) pad[i] ^= 0x36 ^ 0x5c;
	blake2s_init(&x);
	blake2s_update(&x, pad, 64);
	blake2s_update(&x, inner, 32);
	blake2s_final(&x, out);
	wipe(pad, sizeof pad);
	wipe(inner, sizeof inner);
}

/* KDF1..3: t0 = HMAC(C, input); t1 = HMAC(t0, 1); t2 = HMAC(t0, t1 || 2); ... */
static void kdf(uint8_t *o1, uint8_t *o2, uint8_t *o3, const uint8_t ck[32], const uint8_t *in, size_t len)
{
	uint8_t t0[32], t[33];
	hmac(t0, ck, in, len);
	t[0] = 1;
	hmac(t, t0, t, 1);
	if (o1) memcpy(o1, t, 32);
	if (o2 || o3) {
		uint8_t t2[32];
		t[32] = 2;
		hmac(t2, t0, t, 33);
		if (o2) memcpy(o2, t2, 32);
		if (o3) {
			memcpy(t, t2, 32);
			t[32] = 3;
			hmac(o3, t0, t, 33);
		}
		wipe(t2, sizeof t2);
	}
	wipe(t0, sizeof t0);
	wipe(t, sizeof t);
}

static void nonce_ctr(uint8_t n[12], uint64_t c)
{
	memset(n, 0, 4);
	put64le(n + 4, c);
}

static void mix_hash(uint8_t h[32], const uint8_t *d, size_t len)
{
	hash(h, h, 32, d, len);
}

void wg_init(wg_state *s, const uint8_t priv[32], const uint8_t peer[32], const uint8_t psk[32])
{
	memset(s, 0, sizeof *s);
	memcpy(s->priv, priv, 32);
	x25519_base(s->pub, priv);
	memcpy(s->peer_pub, peer, 32);
	if (psk) memcpy(s->psk, psk, 32);
}

void wg_make_initiation(wg_state *s, uint8_t m[WG_INIT_LEN], const uint8_t rnd[32],
                        uint32_t index, const uint8_t tai64n[12])
{
	uint8_t e_pub[32], dh[32], k[32], n[12], mac_key[32];

	memset(m, 0, WG_INIT_LEN);
	m[0] = 1;
	s->local_index = index;
	put32le(m + 4, index);

	hash(s->ck, CONSTRUCTION, sizeof CONSTRUCTION - 1, 0, 0);
	hash(s->h, s->ck, 32, IDENTIFIER, sizeof IDENTIFIER - 1);
	mix_hash(s->h, s->peer_pub, 32);

	memcpy(s->e_priv, rnd, 32);
	x25519_base(e_pub, s->e_priv);
	kdf(s->ck, 0, 0, s->ck, e_pub, 32);
	memcpy(m + 8, e_pub, 32);
	mix_hash(s->h, e_pub, 32);

	x25519(dh, s->e_priv, s->peer_pub);
	kdf(s->ck, k, 0, s->ck, dh, 32);
	nonce_ctr(n, 0);
	aead_seal(m + 40, k, n, s->h, 32, s->pub, 32);
	mix_hash(s->h, m + 40, 48);

	x25519(dh, s->priv, s->peer_pub);
	kdf(s->ck, k, 0, s->ck, dh, 32);
	aead_seal(m + 88, k, n, s->h, 32, tai64n, 12);
	mix_hash(s->h, m + 88, 28);

	/* mac1 = MAC(HASH(LABEL_MAC1 || Spub_r), msg[0:116]); mac2 = 0 */
	hash(mac_key, LABEL_MAC1, sizeof LABEL_MAC1 - 1, s->peer_pub, 32);
	wg_blake2s_keyed(m + 116, 16, mac_key, 32, m, 116);

	memcpy(s->last_init, m, WG_INIT_LEN);
	wipe(dh, sizeof dh);
	wipe(k, sizeof k);
}

int wg_consume_response(wg_state *s, const uint8_t *m, size_t len)
{
	uint8_t ck[32], h[32], dh[32], t[32], k[32], n[12], mac_key[32], mac[16], empty[1];
	uint8_t send_key[32], recv_key[32];

	if (len != WG_RESP_LEN || m[0] != 2 || m[1] || m[2] || m[3]) return -1;
	if (get32le(m + 8) != s->local_index) return -1;

	hash(mac_key, LABEL_MAC1, sizeof LABEL_MAC1 - 1, s->pub, 32);
	wg_blake2s_keyed(mac, 16, mac_key, 32, m, 60);
	if (memcmp(mac, m + 60, 16)) return -1;

	memcpy(ck, s->ck, 32);
	memcpy(h, s->h, 32);
	kdf(ck, 0, 0, ck, m + 12, 32);
	mix_hash(h, m + 12, 32);
	x25519(dh, s->e_priv, m + 12);
	kdf(ck, 0, 0, ck, dh, 32);
	x25519(dh, s->priv, m + 12);
	kdf(ck, 0, 0, ck, dh, 32);
	kdf(ck, t, k, ck, s->psk, 32);
	mix_hash(h, t, 32);
	nonce_ctr(n, 0);
	if (aead_open(empty, k, n, h, 32, m + 44, 16)) {
		wipe(ck, 32); wipe(dh, 32); wipe(k, 32);
		return -1;
	}
	mix_hash(h, m + 44, 16);

	/* initiator: (send, recv) = KDF2(C, empty) */
	kdf(send_key, recv_key, 0, ck, 0, 0);
	memcpy(s->send_key, send_key, 32);
	memcpy(s->recv_key, recv_key, 32);
	s->peer_index = get32le(m + 4);
	s->sess_index = s->local_index;
	s->send_counter = 0;
	s->recv_max = 0;
	memset(s->replay, 0, sizeof s->replay);
	s->have_session = 1;
	wipe(s->e_priv, 32);
	wipe(ck, 32); wipe(dh, 32); wipe(k, 32); wipe(t, 32);
	wipe(send_key, 32); wipe(recv_key, 32);
	return 0;
}

size_t wg_encrypt(wg_state *s, const uint8_t *in, size_t len, uint8_t *out)
{
	uint8_t n[12];
	size_t padded = (len + 15) & ~(size_t)15;
	out[0] = 4; out[1] = out[2] = out[3] = 0;
	put32le(out + 4, s->peer_index);
	put64le(out + 8, s->send_counter);
	if (out + WG_DATA_HDR != in) memmove(out + WG_DATA_HDR, in, len);
	memset(out + WG_DATA_HDR + len, 0, padded - len);
	nonce_ctr(n, s->send_counter);
	aead_seal(out + WG_DATA_HDR, s->send_key, n, 0, 0, out + WG_DATA_HDR, padded);
	s->send_counter++;
	return WG_DATA_HDR + padded + WG_TAG;
}

/* Sliding window of WG_REPLAY_BITS counters (RFC 6479 style, simplified) */
static int replay_check(wg_state *s, uint64_t c)
{
	if (c + WG_REPLAY_BITS <= s->recv_max) return -1;
	if (c > s->recv_max) return 0;
	return (s->replay[(c / 32) % (WG_REPLAY_BITS / 32)] >> (c % 32)) & 1 ? -1 : 0;
}

static void replay_mark(wg_state *s, uint64_t c)
{
	if (c > s->recv_max) {
		uint64_t i;
		uint64_t gap = c - s->recv_max;
		if (gap >= WG_REPLAY_BITS) memset(s->replay, 0, sizeof s->replay);
		else for (i = s->recv_max + 1; i < c; i++) s->replay[(i / 32) % (WG_REPLAY_BITS / 32)] &= ~(1u << (i % 32));
		s->recv_max = c;
	}
	s->replay[(c / 32) % (WG_REPLAY_BITS / 32)] |= 1u << (c % 32);
}

long wg_decrypt(wg_state *s, const uint8_t *m, size_t len, uint8_t *out)
{
	uint8_t n[12];
	uint64_t c;
	if (!s->have_session || len < WG_DATA_HDR + WG_TAG || m[0] != 4) return -1;
	if (get32le(m + 4) != s->sess_index) return -1;
	c = get64le(m + 8);
	if (replay_check(s, c)) return -1;
	nonce_ctr(n, c);
	if (aead_open(out, s->recv_key, n, 0, 0, m + WG_DATA_HDR, len - WG_DATA_HDR)) return -1;
	replay_mark(s, c);
	return (long)(len - WG_DATA_HDR - WG_TAG);
}

int wg_msg_type(const uint8_t *m, size_t len)
{
	if (len < 4 || m[1] || m[2] || m[3]) return 0;
	if (m[0] == 1 && len == WG_INIT_LEN) return 1;
	if (m[0] == 2 && len == WG_RESP_LEN) return 2;
	if (m[0] == 3 && len == 64) return 3;
	if (m[0] == 4 && len >= WG_DATA_HDR + WG_TAG) return 4;
	return 0;
}

void wg_tai64n(uint8_t out[12], uint64_t secs, uint32_t nanos)
{
	uint64_t t = 0x400000000000000aULL + secs;
	int i;
	for (i = 0; i < 8; i++) out[i] = (uint8_t)(t >> (56 - 8 * i));
	for (i = 0; i < 4; i++) out[8 + i] = (uint8_t)(nanos >> (24 - 8 * i));
}
