/* Host test for the mDNS responder's parsing and answer (init/mdns.c).
 * Built by tools/test_wifi_ui.py with -DMDNS_HOST_TEST. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "../ra305x_ap_adv/ra305x_router/init/mdns.c"

int main(void)
{
	static const unsigned char q[] = { 8, 'E', 'x', 't', 'e', 'n', 'd', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0 };
	static const unsigned char other[] = { 4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0 };
	static const unsigned char notlocal[] = { 8, 'e', 'x', 't', 'e', 'n', 'd', 'e', 'r', 3, 'c', 'o', 'm', 0 };
	static const unsigned char bad[] = { 8, 'e', 'x' };
	unsigned char out[128];
	unsigned long a = inet_addr("10.0.1.1");
	int n;

	assert(mdns_match(q, sizeof q, "extender") == (int)sizeof q); /* case-insensitive */
	assert(mdns_match(other, sizeof other, "extender") == 0);
	assert(mdns_match(notlocal, sizeof notlocal, "extender") == 0);
	assert(mdns_match(bad, sizeof bad, "extender") < 0);

	/* multicast answer: id 0, no question, one A record with the address */
	n = mdns_answer(out, 0, q, sizeof q, 0, a);
	assert(out[2] == 0x84 && out[5] == 0 && out[7] == 1);
	assert(!memcmp(out + 12, q, sizeof q));
	assert(out[12 + sizeof q + 1] == 1 && out[12 + sizeof q + 2] == 0x80);
	assert(n == 12 + (int)sizeof q + 10 + 4 && !memcmp(out + n - 4, &a, 4));
	/* legacy unicast: echoes the id and the question */
	n = mdns_answer(out, 0x1234, q, sizeof q, 1, a);
	assert(out[0] == 0x12 && out[1] == 0x34 && out[5] == 1 && n == 12 + 2 * (int)sizeof q + 4 + 10 + 4);
	puts("PASS: mDNS name match (case, .local only) and A answer (multicast and legacy unicast)");
	return 0;
}
