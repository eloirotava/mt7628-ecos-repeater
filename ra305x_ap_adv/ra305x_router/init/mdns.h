/* Minimal mDNS responder (init/mdns.c) */
#ifndef MDNS_H
#define MDNS_H

int mdns_match(const unsigned char *p, int left, const char *name);
int mdns_answer(unsigned char *out, unsigned short id, const unsigned char *qname, int qlen,
                int with_question, unsigned long addr);
void mdns_start(void);

#endif
