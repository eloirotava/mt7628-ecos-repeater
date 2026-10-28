/* ntun inside the MT7628KN extender firmware: configuration, device key,
 * boot thread and status for the web interface.
 *
 * Settings (SYS_NTUN_*) are read once at boot; the web interface saves and
 * restarts. The device key (SYS_NTUN_KEY) is generated here and survives a
 * factory reset; only its public half ever leaves the device. */
#include <cyg/kernel/kapi.h>
#include <network.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cfg_def.h>
#include <cfg_id.h>
#include <cfg_dns.h>
#include "util.h"
#include "noise.h"
#include "ntun_ecos.h"

extern int CFG_get_str(int id, char *val);
extern int CFG_set_str(int id, char *val);
extern int CFG_commit(int id);
extern int CFG_save_user(void);
extern void CFG_get_mac(int id, char *dp);
extern long x_getrandom(void *b, size_t n);
int ntun_client_main(int argc, char **argv);

static volatile int state = NTUN_OFF;
static char status[128] = "Disabled";
static cyg_tick_count_t status_time;
static char key_hex[65], pub_hex[65], resolv[40];
static int have_key;

static cyg_handle_t thread_handle;
static cyg_thread thread_obj;
static char thread_stack[16384];

static void set_status(int s, const char *m)
{
	state = s;
	strncpy(status, m, sizeof status - 1);
	status[sizeof status - 1] = 0;
	status_time = cyg_current_time();
	diag_printf("ntun: %s\n", status);
}

int ntun_ecos_state(void) { return state; }
const char *ntun_ecos_status(void) { return status; }
unsigned ntun_ecos_status_age(void) { return (unsigned)((cyg_current_time() - status_time) / 100); }

int ntun_ecos_public_key(char hex[65])
{
	if (!have_key) { hex[0] = 0; return -1; }
	memcpy(hex, pub_hex, 65);
	return 0;
}

void ntun_ecos_linked(void)
{
	char host[80], port[8], m[128];
	CFG_get_str(CFG_SYS_NTUN_HOST, host);
	CFG_get_str(CFG_SYS_NTUN_PORT, port);
	snprintf(m, sizeof m, "Connected to %s:%s", host, port);
	set_status(NTUN_CONNECTED, m);
}

/* The client logs in Portuguese; show English on the page. */
void ntun_ecos_log(const char *m)
{
	static const struct { const char *needle, *text; int st; } map[] = {
		{ "iniciado", "Connecting", NTUN_CONNECTING },
		{ "dns falhou", "DNS lookup of the server failed; retrying", NTUN_ERROR },
		{ "recusada ou sem rota", "Server unreachable (connection refused or no route); retrying", NTUN_ERROR },
		{ "sem aleatorio", "No random data available", NTUN_ERROR },
		{ "chave nao autorizada", "The server closed the handshake: register this device's public key on the server", NTUN_ERROR },
		{ "nao e o esperado", "Unexpected server: check the server public key", NTUN_ERROR },
		{ "sem resposta da VPS", "Server stopped responding; reconnecting", NTUN_ERROR },
		{ "chave do servidor invalida", "Invalid server public key", NTUN_ERROR },
		{ "chave invalida", "Invalid device key", NTUN_ERROR },
		{ "handshake", "Handshake failed; retrying", NTUN_ERROR },
		{ "escrita", "Write to the server failed; retrying", NTUN_ERROR },
		/* per-session events: the tunnel itself stays up */
		{ "servico local nao responde", 0, -1 },
		{ "quadro invalido", 0, -1 },
		{ "mensagem adulterada", 0, -1 },
	};
	unsigned i;
	diag_printf("%s\n", m);
	for (i = 0; i < sizeof map / sizeof map[0]; i++) {
		if (!strstr(m, map[i].needle)) continue;
		if (map[i].st >= 0) set_status(map[i].st, map[i].text);
		return;
	}
}

/* ------------------------------------------------------------ files */

static int vf_which, vf_off;

long ntun_vfile_open(const char *path)
{
	if (!strcmp(path, "/ntun/key")) {
		if (!have_key) return -ENOENT;
		vf_which = 0;
	} else if (!strcmp(path, "/etc/resolv.conf")) {
		/* DNS server handed out by the upstream DHCP; re-read on every lookup */
		struct in_addr a;
		a.s_addr = DNS_group_get(0);
		if (!a.s_addr) return -ENOENT;
		snprintf(resolv, sizeof resolv, "nameserver %s\n", inet_ntoa(a));
		vf_which = 1;
	} else
		return -ENOENT;
	vf_off = 0;
	return NTUN_VFD_BASE + vf_which;
}

long ntun_vfile_read(int fd, void *b, size_t n)
{
	const char *src = fd == NTUN_VFD_BASE ? key_hex : resolv;
	size_t len = strlen(src);
	if ((size_t)vf_off >= len) return 0;
	if (n > len - vf_off) n = len - vf_off;
	memcpy(b, src + vf_off, n);
	vf_off += n;
	return (long)n;
}

/* ------------------------------------------------------------ boot */

static void hex32(char out[65], const uint8_t in[32])
{
	static const char d[] = "0123456789abcdef";
	int i;
	for (i = 0; i < 32; i++) {
		out[2 * i] = d[in[i] >> 4];
		out[2 * i + 1] = d[in[i] & 15];
	}
	out[64] = 0;
}

static int valid_host(const char *h)
{
	int n = 0;
	for (; *h; h++, n++)
		if (!((*h >= 'a' && *h <= 'z') || (*h >= 'A' && *h <= 'Z') || (*h >= '0' && *h <= '9') || *h == '.' || *h == '-'))
			return 0;
	return n > 0 && n <= 63;
}

static void ntun_thread(cyg_addrword_t arg)
{
	char val[256], host[80], port[8], lport[8], srv[80], mac[6];
	uint8_t key[32], pub[32], seed[32];
	int enabled, dirty = 0;
	char *argv[6];
	(void)arg;

	set_status(NTUN_STARTING, "Starting");

	/* entropy: saved seed, MAC, then timer jitter */
	val[0] = 0;
	CFG_get_str(CFG_SYS_NTUN_SEED, val);
	ntun_entropy_add(val, strlen(val));
	CFG_get_mac(0, mac);
	ntun_entropy_add(mac, sizeof mac);
	ntun_entropy_collect();

	val[0] = 0;
	CFG_get_str(CFG_SYS_NTUN_EN, val);
	enabled = atoi(val) == 1;

	val[0] = 0;
	CFG_get_str(CFG_SYS_NTUN_KEY, val);
	if (unhex32(key, val)) {
		if (x_getrandom(key, 32) != 32) { set_status(NTUN_ERROR, "No random data available"); return; }
		hex32(val, key);
		CFG_set_str(CFG_SYS_NTUN_KEY, val);
		dirty = 1;
	}
	hex32(key_hex, key);
	noise_public_key(pub, key);
	memset(key, 0, sizeof key);
	hex32(pub_hex, pub);
	have_key = 1;

	/* renew the seed so the next boot does not start from the same state */
	if (enabled || dirty) {
		x_getrandom(seed, 32);
		hex32(val, seed);
		memset(seed, 0, sizeof seed);
		CFG_set_str(CFG_SYS_NTUN_SEED, val);
		CFG_commit(CFG_NO_EVENT);
		if (CFG_save_user()) diag_printf("ntun: saving key/seed failed\n");
	}

	if (!enabled) { set_status(NTUN_OFF, "Disabled"); return; }

	val[0] = 0;
	CFG_get_str(CFG_SYS_ADMPASS, val);
	if (!val[0]) { set_status(NTUN_ERROR, "Not started: set an admin password first"); return; }

	CFG_get_str(CFG_SYS_NTUN_HOST, host);
	CFG_get_str(CFG_SYS_NTUN_PORT, port);
	CFG_get_str(CFG_SYS_NTUN_LPORT, lport);
	CFG_get_str(CFG_SYS_NTUN_SRVKEY, srv);
	if (!valid_host(host) || atoi(port) < 1 || atoi(port) > 65535 || unhex32(pub, srv)) {
		set_status(NTUN_ERROR, "Not started: check server, port and server public key");
		return;
	}
	if (strcmp(lport, "23")) strcpy(lport, "80");

	argv[0] = "ntun"; argv[1] = lport; argv[2] = "/ntun/key";
	argv[3] = host; argv[4] = port; argv[5] = srv;
	ntun_client_main(6, argv);
	/* only returns on a configuration error, already reported by x_log */
	if (state != NTUN_ERROR) set_status(NTUN_ERROR, "Stopped");
}

void ntun_ecos_start(void)
{
	cyg_thread_create(14, ntun_thread, 0, "ntun", thread_stack, sizeof thread_stack,
	                  &thread_handle, &thread_obj);
	cyg_thread_resume(thread_handle);
}
