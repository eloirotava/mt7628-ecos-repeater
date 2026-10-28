/* wg0: network interface for the WireGuard tunnel (pattern of if_loop.c).
 * Output queues IPv4 packets on if_snd for the WireGuard thread; input hands
 * decrypted packets to IP through ipintrq. No ARP; the address and mask set
 * on wg0 give the connected route to the tunnel network. */
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <cyg/kernel/kapi.h>
#include "wg_ecos.h"

#define WG_MTU 1420

static struct ifnet wg_ifnet;
static cyg_sem_t *tx_wake;

static int wg_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst, struct rtentry *rt)
{
	int s;
	(void)rt;
	if (dst->sa_family != AF_INET) { m_freem(m); return EAFNOSUPPORT; }
	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) { m_freem(m); return ENETDOWN; }
	s = splimp();
	if (IF_QFULL(&ifp->if_snd)) {
		IF_DROP(&ifp->if_snd);
		ifp->if_oerrors++;
		splx(s);
		m_freem(m);
		return ENOBUFS;
	}
	IF_ENQUEUE(&ifp->if_snd, m);
	splx(s);
	if (tx_wake) cyg_semaphore_post(tx_wake);
	return 0;
}

static int wg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifreq *ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP | IFF_RUNNING;
		return 0;
	case SIOCSIFMTU:
		if (ifr->ifr_mtu < 576 || ifr->ifr_mtu > WG_MTU) return EINVAL;
		ifp->if_mtu = ifr->ifr_mtu;
		return 0;
	case SIOCSIFFLAGS:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		return 0;
	default:
		return EINVAL;
	}
}

void wg_if_attach(cyg_sem_t *wake)
{
	struct ifnet *ifp = &wg_ifnet;
	tx_wake = wake;
	ifp->if_name = "wg";
	ifp->if_unit = 0;
	ifp->if_mtu = WG_MTU;
	ifp->if_flags = IFF_NOARP | IFF_MULTICAST;
	ifp->if_ioctl = wg_ioctl;
	ifp->if_output = wg_output;
	ifp->if_type = IFT_PROPVIRTUAL;
	IFQ_SET_MAXLEN(&ifp->if_snd, 64);
	IFQ_SET_READY(&ifp->if_snd);
	if_attach(ifp);
}

/* Next queued IPv4 packet copied into buf; 0 when the queue is empty. */
int wg_if_dequeue(unsigned char *buf, int max)
{
	struct mbuf *m;
	int s, len;
	s = splimp();
	IF_DEQUEUE(&wg_ifnet.if_snd, m);
	splx(s);
	if (!m) return 0;
	len = m->m_pkthdr.len;
	if (len > max) {
		wg_ifnet.if_oerrors++;
		m_freem(m);
		return -1;
	}
	m_copydata(m, 0, len, (caddr_t)buf);
	m_freem(m);
	wg_ifnet.if_opackets++;
	wg_ifnet.if_obytes += len;
	return len;
}

/* Drop everything queued (tunnel down). */
void wg_if_flush(void)
{
	struct mbuf *m;
	int s;
	for (;;) {
		s = splimp();
		IF_DEQUEUE(&wg_ifnet.if_snd, m);
		splx(s);
		if (!m) break;
		m_freem(m);
	}
}

/* Hand a decrypted IPv4 packet to the stack. */
void wg_if_input(unsigned char *buf, int len)
{
	struct mbuf *m;
	int s;
	if (len < 20 || (buf[0] >> 4) != 4) { wg_ifnet.if_ierrors++; return; }
	m = m_devget((char *)buf, len, 0, &wg_ifnet, 0);
	if (!m) { wg_ifnet.if_iqdrops++; return; }
	s = splimp();
	if (IF_QFULL(&ipintrq)) {
		IF_DROP(&ipintrq);
		splx(s);
		m_freem(m);
		return;
	}
	IF_ENQUEUE(&ipintrq, m);
	schednetisr(NETISR_IP);
	wg_ifnet.if_ipackets++;
	wg_ifnet.if_ibytes += len;
	splx(s);
}

void wg_if_counters(unsigned long *rx_bytes, unsigned long *tx_bytes)
{
	*rx_bytes = wg_ifnet.if_ibytes;
	*tx_bytes = wg_ifnet.if_obytes;
}
