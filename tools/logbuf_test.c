/* Host test for the console ring and syslog server parsing (init/logbuf.c).
 * Built by tools/test_wifi_ui.py with -DLOGBUF_HOST_TEST. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "../ra305x_ap_adv/ra305x_router/init/logbuf.c"

int main(void)
{
	static char out[LOG_SIZE + 16];
	unsigned long ip;
	unsigned short port;
	int i, n;
	const char *m = "wg: Connected\n";

	assert(logbuf_read(out, sizeof out) == 0 && out[0] == 0);
	for (i = 0; m[i]; i++) logbuf_putc(m[i]);
	n = logbuf_read(out, sizeof out);
	assert(n == (int)strlen(m) && !strcmp(out, m));
	/* a small buffer gets the newest characters */
	assert(logbuf_read(out, 5) == 4 && !strcmp(out, "ted\n"));
	/* overflow keeps the newest LOG_SIZE characters, oldest first */
	for (i = 0; i < LOG_SIZE * 2; i++) logbuf_putc((char)('a' + i % 26));
	n = logbuf_read(out, sizeof out);
	assert(n == LOG_SIZE && out[n - 1] == (char)('a' + (LOG_SIZE * 2 - 1) % 26) && out[0] == (char)('a' + LOG_SIZE % 26));

	assert(!logbuf_parse_server("10.8.0.1", &ip, &port) && ip == inet_addr("10.8.0.1") && port == htons(514));
	assert(!logbuf_parse_server("10.8.0.1:5514", &ip, &port) && port == htons(5514));
	assert(logbuf_parse_server("10.8.0.1:0", &ip, &port) && logbuf_parse_server("host:514", &ip, &port) && logbuf_parse_server("", &ip, &port));
	assert(logbuf_parse_server("0.0.0.0", &ip, &port) && logbuf_parse_server("10.8.0.1:70000", &ip, &port));
	puts("PASS: console log ring (order, overflow) and syslog server parsing");
	return 0;
}
