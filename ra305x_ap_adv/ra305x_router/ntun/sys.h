/* Chamadas de sistema do cliente, no estilo do kernel: >= 0 ok, -errno erro.
 * sys_libc.c: pela libc (PC, testes). sys_nolibc.c + mips.S: direto no
 * kernel, sem libc (roteador). Constantes e structs vem dos cabecalhos do
 * sistema alvo (no MIPS, SOCK_STREAM, SOL_SOCKET e os errno sao outros). */
#ifndef NTUN_SYS_H
#define NTUN_SYS_H

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#ifdef NTUN_ECOS
/* eCos (MT7628KN extender firmware): BSD stack, no poll(); see sys_ecos.c */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
struct pollfd { int fd; short events, revents; };
#define POLLIN  0x001
#define POLLOUT 0x004
#define POLLERR 0x008
#define POLLHUP 0x010
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
/* Not in this stack; setsockopt fails and the client carries on. */
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE  0x7f01
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 0x7f02
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT   0x7f03
#endif
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

long x_socket(int domain, int type, int proto);
long x_connect(int fd, const struct sockaddr_in *a);
long x_setsockopt(int fd, int level, int opt, const void *v, unsigned len);
long x_poll(struct pollfd *fds, unsigned n, int ms);
long x_read(int fd, void *b, size_t n);
long x_write(int fd, const void *b, size_t n);
long x_sendto(int fd, const void *b, size_t n, const struct sockaddr_in *a);
long x_recv(int fd, void *b, size_t n, int flags);
long x_recvfrom(int fd, void *b, size_t n, int flags, struct sockaddr_in *from);
long x_bind(int fd, const struct sockaddr_in *a);
long x_close(int fd);
long x_open(const char *path);   /* so leitura */
long x_getrandom(void *b, size_t n);
long x_now(void);                /* segundos, relogio monotonico */
void x_sleep(unsigned s);
void x_log(const char *m);       /* stderr + \n */

#endif
