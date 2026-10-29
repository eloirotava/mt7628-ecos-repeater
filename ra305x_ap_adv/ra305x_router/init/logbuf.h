/* Console log in RAM and to a remote syslog server (init/logbuf.c) */
#ifndef LOGBUF_H
#define LOGBUF_H

void logbuf_putc(char c);
int logbuf_read(char *out, int size);
int logbuf_parse_server(const char *s, unsigned long *ip, unsigned short *port);
void logbuf_capture(void);
void logbuf_start(void);

#endif
