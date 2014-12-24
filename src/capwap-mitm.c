/*
 *  This file is part of capwap-mitm.
 *
 *  Foobar is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  capwap-mitm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with capwap-mitm.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _REENTRANT

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/tree.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <ev.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>

#include "log.h"

static const char _ident[] = "capwap-mitm v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

#define MAX_BUFFER  2048

struct sockaddr_storage server_addr;
struct sockaddr_storage listen_addr;

#if !defined(CERTSDIR)
#define CERTSDIR "certs"
#endif

const char *dtls_server_keyfile  = CERTSDIR "/server.key";
const char *dtls_server_certfile = CERTSDIR "/server.pem";
const char *dtls_client_keyfile  = CERTSDIR "/client.key";
const char *dtls_client_certfile = CERTSDIR "/client.pem";
const char *dtls_cafile          = CERTSDIR "/cacerts.pem";
const char *dtls_crlfile         = CERTSDIR "/crl.pem";

const char *pcap_fname = NULL;
pcap_dumper_t *dumper = NULL;

gnutls_certificate_credentials_t x509_server_cred;
gnutls_certificate_credentials_t x509_client_cred;
gnutls_priority_t priority_cache;
gnutls_dh_params_t dh_params;
gnutls_datum_t cookie_key;

pcap_t *pcap;

struct capwap_port {
	int port;

	int listen_fd;
	ev_io listen_ev;
};

struct dtls_session {
	int fd;

	int is_connected;

	struct sockaddr_storage peer_addr;
	socklen_t peer_addrlen;

	int handshake_done;
	gnutls_session_t session;

	const unsigned char *buffer;
	ssize_t buffer_len;
};

struct wtp {
	struct sockaddr_storage addr;
	struct capwap_port *capwap_port;

        RB_ENTRY (wtp) wtp_node;
	ev_timer timeout;
	ev_io client_ev;

	struct dtls_session server;
	struct dtls_session client;
};

static ssize_t dtls_push_func(gnutls_transport_ptr_t p, const void *data, size_t size);
static ssize_t dtls_pull_func(gnutls_transport_ptr_t p, void *data, size_t size);
static int dtls_pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms);

static int wtp_addr_compare(struct wtp *a, struct wtp *b);

RB_HEAD(wtp_tree, wtp) wtp_tree;
RB_PROTOTYPE(wtp_tree, wtp, wtp_node, wtp_addr_compare);
RB_GENERATE(wtp_tree, wtp, wtp_node, wtp_addr_compare);

#if !defined(offsetof)
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
#define container_of(var, type, member) (type *)(((unsigned char *)var) - offsetof(type, member))

#define SIN_ADDR_PTR(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (void *)&(((struct sockaddr_in *)(addr))->sin_addr) : (void *)&(((struct sockaddr_in6 *)(addr))->sin6_addr))
#define SIN_PORT(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (((struct sockaddr_in *)(addr))->sin_port) : (((struct sockaddr_in6 *)(addr))->sin6_port))

#define INT_CMP(A, B)                                    \
        ({						 \
                typeof(A) a_ = (A);			 \
                typeof(B) b_ = (B);			 \
                a_ < b_ ? -1 : (a_ > b_ ? 1 : 0);	 \
        })

#define SOCK_ADDR_CMP(a, b, socktype, field)				\
	memcmp(&(((struct socktype *)(a))->field),			\
	       &(((struct socktype *)(b))->field),			\
	       sizeof(((struct socktype *)(a))->field))

#define SOCK_PORT_CMP(a, b, socktype, field)				\
	INT_CMP(((struct socktype *)(a))->field, ((struct socktype *)(b))->field)

static int wtp_addr_compare(struct wtp *a, struct wtp *b)
{
	int r;

	if ((r = INT_CMP(a->addr.ss_family, b->addr.ss_family)) != 0)
		return r;

	switch (a->addr.ss_family) {
	case AF_INET:
		if (SOCK_ADDR_CMP(&a->addr, &b->addr, sockaddr_in, sin_addr) != 0)
			return 0;
		return SOCK_PORT_CMP(&a->addr, &b->addr, sockaddr_in, sin_port);

	case AF_INET6:
		if (SOCK_ADDR_CMP(&a->addr, &b->addr, sockaddr_in6, sin6_addr) != 0)
			return 0;
		return SOCK_PORT_CMP(&a->addr, &b->addr, sockaddr_in6, sin6_port);
	}

	return 0;
}

static uint32_t cksum_part(uint8_t *ip, int len, uint32_t sum)
{
        while (len > 1) {
                sum += *(uint16_t *)ip;
                if (sum & 0x80000000)   /* if high order bit set, fold */
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
                ip += 2;
        }

        if (len)       /* take care of left over byte */
                sum += (uint16_t) *(uint8_t *)ip;

        return sum;
}

static uint16_t cksum_finish(uint32_t sum)
{
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}

static uint16_t cksum(uint8_t *ip, int len)
{
        return cksum_finish(cksum_part(ip, len, 0));
}

static void capwap_dump(struct sockaddr *src, struct sockaddr *dst, const unsigned char *buffer, ssize_t len)
{
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

	if (!dumper)
		return;

	debug("src: %d, dst: %d", src->sa_family, dst->sa_family);
/*
#if defined(DEBUG)
		inet_ntop(s->peer_addr.ss_family, SIN_ADDR_PTR(&s->peer_addr), ipaddr, sizeof(ipaddr));
		debug("DTLS PUSH on %d to IP: %s:%d, len: %zd\n", s->fd, ipaddr, ntohs(SIN_PORT(&s->peer_addr)), size);
#endif
*/

	if (src->sa_family == AF_INET) {
		struct pcap_pkthdr hdr;
		unsigned char *pkt = alloca(sizeof(struct iphdr)  + sizeof(struct udphdr) + len);
		struct iphdr *iph = (struct iphdr *)pkt;
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		memset(pkt, 0, sizeof(struct iphdr)  + sizeof(struct udphdr) + len);

		iph->version = 4;
		iph->ihl = sizeof(struct iphdr) / 4;
		iph->protocol = IPPROTO_UDP;
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);
		iph->ttl = 64;
		iph->saddr = ((struct sockaddr_in *)src)->sin_addr.s_addr;
		iph->daddr = ((struct sockaddr_in *)dst)->sin_addr.s_addr;
		iph->check = cksum((uint8_t *)iph, sizeof(struct iphdr));

		udph->source = ((struct sockaddr_in *)src)->sin_port;
		udph->dest = ((struct sockaddr_in *)dst)->sin_port;
		udph->len = htons(sizeof(struct udphdr) + len);

		memcpy(udph + 1, buffer, len);

		udph->check = cksum((uint8_t *)udph, sizeof(struct udphdr) + len);

		memset(&hdr, 0, sizeof(hdr));
		gettimeofday(&hdr.ts, NULL);
		hdr.caplen = hdr.len = sizeof(struct iphdr)  + sizeof(struct udphdr) + len;

		pcap_dump((u_char *)dumper, &hdr, pkt);
	} else {
		struct pcap_pkthdr hdr;
		unsigned char *pkt = alloca(sizeof(struct ip6_hdr)  + sizeof(struct udphdr) + len);
		struct ip6_hdr *iph = (struct ip6_hdr *)pkt;
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		iph->ip6_vfc = 6;
		iph->ip6_nxt = IPPROTO_UDP;
		iph->ip6_plen = ntohs(sizeof(struct udphdr) + len);
		memcpy(&iph->ip6_src, &((struct sockaddr_in6 *)src)->sin6_addr, sizeof(struct in6_addr));
		memcpy(&iph->ip6_dst, &((struct sockaddr_in6 *)dst)->sin6_addr, sizeof(struct in6_addr));

		udph->source = ((struct sockaddr_in6 *)src)->sin6_port;
		udph->dest = ((struct sockaddr_in6 *)dst)->sin6_port;
		udph->len = htons(sizeof(struct udphdr) + len);

		memcpy(udph + 1, buffer, len);

		udph->check = cksum((uint8_t *)udph, sizeof(struct udphdr) + len);

		memset(&hdr, 0, sizeof(hdr));
		gettimeofday(&hdr.ts, NULL);
		hdr.caplen = hdr.len = sizeof(struct ip6_hdr)  + sizeof(struct udphdr) + len;

		pcap_dump((u_char *)dumper, &hdr, pkt);
	}

}

static void capwap_server_in(EV_P_ struct capwap_port *capwap_port, unsigned char *buffer, ssize_t len, struct sockaddr *addr, socklen_t addrlen);
static void capwap_fwd(struct wtp *wtp, unsigned char *buffer, ssize_t len);

static void capwap_server_cb(EV_P_ ev_io *ev, int revents)
{
	ssize_t r;
	struct capwap_port *capwap_port = container_of(ev, struct capwap_port, listen_ev);
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	unsigned char buffer[2048];

	debug("read (%x) from %d", revents, ev->fd);

	do {
		r = recvfrom(ev->fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&addr, &addrlen);
		if (r < 0) {
			if (errno == EAGAIN)
				break;
			else if (errno == EINTR)
				continue;

			debug("capwap read error: %m");
			return;
		} else
			capwap_server_in(EV_A_ capwap_port, buffer, r, (struct sockaddr *)&addr, addrlen);
	} while (42);
}

static void wtp_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	struct wtp *wtp = container_of(w, struct wtp, timeout);

	debug("got timeout for WTP at %p", wtp);

	ev_timer_stop (EV_A_ w);
	ev_io_stop (EV_A_ &wtp->client_ev);
	if (wtp->server.fd)
		close(wtp->server.fd);

	RB_REMOVE(wtp_tree, &wtp_tree, wtp);
	free(wtp);
}

static void capwap_client_cb(EV_P_ ev_io *ev, int revents)
{
	ssize_t r;
	struct wtp *wtp = container_of(ev, struct wtp, client_ev);
	unsigned char buffer[2048];

	debug("read (%x) from %d", revents, ev->fd);

	do {
		r = recv(ev->fd, buffer, sizeof(buffer), MSG_DONTWAIT);
		if (r < 0) {
			if (errno == EAGAIN)
				break;
			else if (errno == EINTR)
				continue;

			debug("capwap read error: %m");
			return;
		} else
			capwap_fwd(wtp, buffer, r);
	} while (42);

	/* reset timeout */
	ev_timer_again(EV_A_ &wtp->timeout);
}

static void adjust_control_ips(unsigned char *buffer, ssize_t len)
{
	int hlen;

	if (buffer[0] != 0)
		return;

	/* plain capwap */

	/* Adjust CAPWAP Control IPv4 Address in Discover Response messages */
	hlen = ((buffer[1] & 0xf8) >> 3) * 4;
	if (len > hlen) {
		unsigned char *m = buffer + hlen;

		if (ntohl(*(uint32_t *)m) == 2) {   /* discover response */
			int mlen;

			mlen = ntohs(*(uint16_t *)(m + 5));
			fprintf(stderr, "mlen: %d\n", mlen);
			m += 8;

			while (mlen > 0) {
				int type;
				int ielen;

				type = ntohs(*(uint16_t *)m);
				ielen =  ntohs(*(uint16_t *)(m + 2)) + 4;

				if (type == 10 && listen_addr.ss_family == AF_INET) {  /* CAPWAP Control IPv4 Address */
					memcpy(m + 4, &((struct sockaddr_in *)&listen_addr)->sin_addr, 4);
				}
				mlen -= ielen;
				m += ielen;
			}
		}
	}
}

static void plain_forward(struct dtls_session *recv, struct dtls_session *send_s, unsigned char *buffer, ssize_t len)
{
	int ret;

	capwap_dump((struct sockaddr *)&recv->peer_addr, (struct sockaddr *)&send_s->peer_addr, buffer, len);
	adjust_control_ips(buffer, len);

	if (send_s->is_connected) {
		ret = send(send_s->fd, buffer, len, MSG_DONTWAIT);
	} else
		ret = sendto(send_s->fd, buffer, len, MSG_DONTWAIT, (struct sockaddr *)&send_s->peer_addr, send_s->peer_addrlen);

	if (ret < 0)
		fprintf(stderr, "%s(%d): %m", !send_s->peer_addrlen ? "send" : "sendto", send_s->fd);
}

static void dtls_forward(struct dtls_session *recv, struct dtls_session *send_s, unsigned char *buffer, ssize_t len)
{
	int ret;

	recv->buffer = buffer;
	recv->buffer_len = len;

	if (!recv->handshake_done) {
		do {
			ret = gnutls_handshake(recv->session);
			debug("DTLS handshake on session %p, fd %d, got %d", recv, recv->fd, ret);
		} while (ret == GNUTLS_E_INTERRUPTED);

		if (ret < 0) {
			if (ret != GNUTLS_E_AGAIN) {
				fprintf(stderr, "Error in handshake(): %s\n", gnutls_strerror(ret));
				gnutls_deinit(recv->session);
				return;
			}
		}
		if (ret == GNUTLS_E_SUCCESS)
			recv->handshake_done = 1;
	} else {
		unsigned char sequence[8];
		unsigned char plain_text[MAX_BUFFER];

		do {
			ret = gnutls_record_recv_seq(recv->session, plain_text, sizeof(plain_text), sequence);
			debug("DTLS record recv on session %p, fd %d, got %d", recv, recv->fd, ret);
		} while (ret == GNUTLS_E_INTERRUPTED);

		if (ret < 0 && ret != GNUTLS_E_AGAIN) {
			if (gnutls_error_is_fatal(ret) == 0) {
				fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
			} else {
				fprintf(stderr, "Error in recv(): %s\n", gnutls_strerror(ret));
				gnutls_deinit(recv->session);
			}
			return;
		}

		debug("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]",
		      sequence[0], sequence[1], sequence[2],
		      sequence[3], sequence[4], sequence[5],
		      sequence[6], sequence[7]);
//				hexdump(plain_text, ret);

		capwap_dump((struct sockaddr *)&recv->peer_addr, (struct sockaddr *)&send_s->peer_addr, plain_text, ret);
		adjust_control_ips(plain_text, ret);

		debug("DTLS record send on session %p, fd %d", send_s, send_s->fd);
		ret = gnutls_record_send(send_s->session, plain_text, ret);
		debug("GnuTLS send: %d", ret);
	}
}

static void capwap_server_in(EV_P_ struct capwap_port *capwap_port, unsigned char *buffer, ssize_t len, struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	struct wtp *wtp;
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

#if defined(DEBUG)
	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	debug("on %d (%d) got CAPWAP data from IP: %s:%d, len: %zd\n", capwap_port->listen_fd, capwap_port->port, ipaddr, ntohs(SIN_PORT(addr)), len);
#endif

	if (!(wtp = RB_FIND(wtp_tree, &wtp_tree, (struct wtp *)addr))) {
		int on = 1;
		struct sockaddr_storage saddr;
		socklen_t saddr_len = sizeof(saddr);

		wtp = calloc(1, sizeof(struct wtp));
		if (!wtp)
			return;  /* OOM */

		memcpy(&wtp->addr, addr, addrlen);
		wtp->capwap_port = capwap_port;
		wtp->server.fd = capwap_port->listen_fd;
		wtp->server.peer_addrlen = addrlen;
		memcpy(&wtp->server.peer_addr, addr, addrlen);

		ev_init(&wtp->timeout, wtp_timeout_cb);
		wtp->timeout.repeat = 120.;

		if ((wtp->client.fd = socket(server_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}
		setsockopt(wtp->client.fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
#if !defined(SO_REUSEPORT)
#       warning "SO_REUSEPORT undefined, please upgrade to a newer kernel"
#else
		setsockopt(wtp->client.fd, SOL_SOCKET, SO_REUSEPORT, (char*)&on, sizeof(on));
#endif
		setsockopt(wtp->client.fd, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on));
		// setsockopt(wtp->client.fd, SOL_IP, IPV6_V6ONLY,(char*)&on, sizeof(on));

		on = IP_PMTUDISC_DO;
		setsockopt(wtp->client.fd, SOL_IP, IP_MTU_DISCOVER,  (char*)&on, sizeof(on));

		if (server_addr.ss_family == AF_INET)
			((struct sockaddr_in *)&server_addr)->sin_port = htons(capwap_port->port);
		else
			((struct sockaddr_in6 *)&server_addr)->sin6_port = htons(capwap_port->port);

		if (connect(wtp->client.fd, (struct sockaddr *)&server_addr, server_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0) {
			perror("connect");
			exit(EXIT_FAILURE);
		}

		wtp->client.is_connected = 1;
		wtp->client.peer_addrlen = sizeof(wtp->client.peer_addr);
		getpeername(wtp->client.fd, (struct sockaddr *)&wtp->client.peer_addr, &wtp->client.peer_addrlen);

		getsockname(wtp->client.fd, (struct sockaddr *)&saddr, &saddr_len);
		printf("opened CAPWAP server port on %d to %d\n", ntohs(SIN_PORT(&saddr)), capwap_port->port);

		RB_INSERT(wtp_tree, &wtp_tree, wtp);

		ev_io_init(&wtp->client_ev, capwap_client_cb, wtp->client.fd, EV_READ);
		ev_io_start(EV_DEFAULT_ &wtp->client_ev);
	}

	debug("got WTP at %p", wtp);

	if (buffer[0] == 0) { /* plain capwap */
		plain_forward(&wtp->server, &wtp->client, buffer, len);
	}
	else if (buffer[0] == 0x01) { /* DTLS capwap */
		struct dtls_session *s = &wtp->server;
		struct dtls_session *c = &wtp->client;

		if (!s->session) {
			gnutls_dtls_prestate_st prestate;

			memset(&prestate, 0, sizeof(prestate));
			ret = gnutls_dtls_cookie_verify(&cookie_key, (void *)addr, addrlen, (unsigned char*)buffer + 4, len - 4, &prestate);

			if (ret < 0) {  /* cookie not valid */
				gnutls_dtls_cookie_send(&cookie_key, (void *)addr, addrlen, &prestate,
							(gnutls_transport_ptr_t)s, dtls_push_func);
				goto out;
			} else {
				debug("server: %p, client: %p", s, c);

				gnutls_init(&s->session, GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
				gnutls_priority_set(s->session, priority_cache);
				gnutls_credentials_set(s->session, GNUTLS_CRD_CERTIFICATE, x509_server_cred);

				/* prestate is only used to cary to write seq number forward, the buffer will be processed again in dtls_forward ! */

				gnutls_dtls_prestate_set(s->session, &prestate);
				gnutls_dtls_set_mtu(s->session, 1500);

				gnutls_transport_set_ptr(s->session, s);
				gnutls_transport_set_push_function(s->session, dtls_push_func);
				gnutls_transport_set_pull_function(s->session, dtls_pull_func);
				gnutls_transport_set_pull_timeout_function(s->session, dtls_pull_timeout_func);

				gnutls_init(&c->session, GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
				gnutls_priority_set(c->session, priority_cache);
				gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, x509_client_cred);

				gnutls_dtls_set_mtu(c->session, 1500);

				gnutls_transport_set_ptr(c->session, c);
				gnutls_transport_set_push_function(c->session, dtls_push_func);
				gnutls_transport_set_pull_function(c->session, dtls_pull_func);
				gnutls_transport_set_pull_timeout_function(c->session, dtls_pull_timeout_func);

				/* Perform the TLS handshake */
				do {
					ret = gnutls_handshake(c->session);
					debug("initial Client DTLS handshake on session %p, fd %d, got %d", c, c->fd, ret);
				}
				while (ret == GNUTLS_E_INTERRUPTED);
				if (ret < 0 && ret != GNUTLS_E_AGAIN) {
					fprintf(stderr, "*** Client Handshake failed\n");
					gnutls_perror(ret);
					goto out;
				}
			}
		}

		dtls_forward(s, &wtp->client, buffer + 4, len - 4);
	}

out:
	/* reset timeout */
	ev_timer_again(EV_A_ &wtp->timeout);
}

static void capwap_fwd(struct wtp *wtp, unsigned char *buffer, ssize_t len)
{
	if (buffer[0] == 0) { /* plain capwap */
		plain_forward(&wtp->client, &wtp->server, buffer, len);
	}
	else if (buffer[0] == 0x01) /* DTLS capwap */
		dtls_forward(&wtp->client, &wtp->server, buffer + 4, len - 4);
}

/* DTLS functions */

static ssize_t dtls_push_func(gnutls_transport_ptr_t p, const void *data, size_t size)
{
	struct dtls_session *s = p;

	ssize_t r __attribute__((unused));
	struct iovec iov[2];
	struct msghdr mh;
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

	unsigned char preamble[4] = {1, 0, 0, 0};

	debug("%p: DTLS push of size %zd", s, size);

	/* The message header contains parameters for sendmsg.    */
	memset(&mh, 0, sizeof(mh));
	if (!s->is_connected) {

#if defined(DEBUG)
		inet_ntop(s->peer_addr.ss_family, SIN_ADDR_PTR(&s->peer_addr), ipaddr, sizeof(ipaddr));
		debug("DTLS PUSH on %d to IP: %s:%d, len: %zd\n", s->fd, ipaddr, ntohs(SIN_PORT(&s->peer_addr)), size);
#endif

		mh.msg_name = (caddr_t)&s->peer_addr;
		mh.msg_namelen = s->peer_addrlen;
	} else
		  debug("DTLS PUSH on %d, len: %zd\n", s->fd, size);

	mh.msg_iov = iov;
	mh.msg_iovlen = 2;

	iov[0].iov_base = &preamble;
	iov[0].iov_len = sizeof(preamble);

	iov[1].iov_base = (unsigned char *)data;
	iov[1].iov_len = size;

	/* FIXME: shortcat write, we do want to use NON-BLOCKING send here and
	 *        switch to write_ev should it block....
        */
	if ((r = sendmsg(s->fd, &mh, MSG_DONTWAIT)) < 0) {
		debug("sendmsg on %d: %m", s->fd);
		return r;
	} else {
		debug("sendmsg on %d: %zd", s->fd, r);
		return (r - sizeof(preamble));
	}
}

static ssize_t dtls_pull_func(gnutls_transport_ptr_t p, void *data, size_t size)
{
        struct dtls_session *s = p;

	debug("%p: DTLS pull of size %zd", s, size);

	if (!s->buffer) {
		gnutls_transport_set_errno(s->session, EAGAIN);
		return -1;
	}

	if (size < s->buffer_len) {
		debug("######################## pull too short: want %zd, have %zd", size, s->buffer_len);
		return -1;
	}

	memcpy(data, s->buffer, s->buffer_len);
	s->buffer = NULL;
	return s->buffer_len;
}

static int dtls_pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms)
{
        struct dtls_session *s = p;

	debug("%p: DTLS pull timeout", s);

	if (s->buffer)
                return 1;        /* data available */

	return 0;                /* timeout */
}

static void bind_capwap(struct capwap_port *capwap_port)
{
	int on = 1;

	if (listen_addr.ss_family == AF_INET)
		((struct sockaddr_in *)&listen_addr)->sin_port = htons(capwap_port->port);
	else
		((struct sockaddr_in6 *)&listen_addr)->sin6_port = htons(capwap_port->port);

	if ((capwap_port->listen_fd = socket(listen_addr.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(capwap_port->listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
#if !defined(SO_REUSEPORT)
#       warning "SO_REUSEPORT undefined, please upgrade to a newer kernel"
#else
	setsockopt(capwap_port->listen_fd, SOL_SOCKET, SO_REUSEPORT, (char*)&on, sizeof(on));
#endif
	setsockopt(capwap_port->listen_fd, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on));
	// setsockopt(capwap_port->listen_fd, SOL_IP, IPV6_V6ONLY,(char*)&on, sizeof(on));

	on = IP_PMTUDISC_DO;
	setsockopt(capwap_port->listen_fd, SOL_IP, IP_MTU_DISCOVER,  (char*)&on, sizeof(on));

	if (bind(capwap_port->listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	printf("opened CAPWAP listening port %d on fd %d\n", capwap_port->port, capwap_port->listen_fd);

	ev_io_init(&capwap_port->listen_ev, capwap_server_cb, capwap_port->listen_fd, EV_READ);
	ev_io_start(EV_DEFAULT_ &capwap_port->listen_ev);
}

static void ip_to_addr(const char *ip, struct sockaddr *addr)
{
	if (strchr(ip, ':') == NULL) {
		addr->sa_family = AF_INET;
		if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)addr)->sin_addr) <= 0) {
			fprintf(stderr, "%s: Not in presentation format\n", ip);
			exit(EXIT_FAILURE);
		}
	} else {
		addr->sa_family = AF_INET6;
		if (inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)addr)->sin6_addr) <= 0) {
			fprintf(stderr, "%s: Not in presentation format\n", ip);
			exit(EXIT_FAILURE);
		}
	}
}

static void sigint_cb (struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break (loop, EVBREAK_ALL);
}

static void usage(void)
{
        printf("TPLINO CAPWAP MITM Debug Proxy, Version: .....\n\n"
               "Usage: capwap-mitm [OPTION...] LISTEN-IP SERVER-IP \n\n"
               "Options:\n\n"
               "  -h                                this help\n"
	       "  -p, --port=PORT                   open CAPWAP MITM proxy on PORT\n"
	       "  -o FILE                           write pcap to FILE\n"
	       "  --server-key=FILE                 DTLS server certificate key\n"
	       "  --server-cert=FILE                DTLS server certificate\n"
	       "  --client-key=FILE                 DTLS client certificate key\n"
	       "  --client-cert=FILE                DTLS client certificate\n"
	       "  --cafile=FILE                     DTLS CA chain file\n"
	       "  --crl=FILE                        DTLS CRL file\n"
               "\n");

        exit(EXIT_SUCCESS);
}

#define BLOCK_ALLOC 16

int main(int argc, char *argv[])
{
        const struct rlimit rlim = {
                .rlim_cur = RLIM_INFINITY,
                .rlim_max = RLIM_INFINITY
        };

	ev_signal signal_watcher;

	int c;
	int i;
	int capwap_cnt = 0;
	struct capwap_port *capwap_port = NULL;
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

        /* unlimited size for cores */
        setrlimit(RLIMIT_CORE, &rlim);

        while (1) {
                int option_index = 0;
                static struct option long_options[] = {
                        {"port",          1, 0, 'p'},
                        {"server-key",    1, 0,  1024},
                        {"server-cert",   1, 0,  1025},
                        {"cafile",        1, 0,  1026},
                        {"crl",           1, 0,  1027},
                        {"client-key",    1, 0,  1028},
                        {"client-cert",   1, 0,  1029},
                        {0, 0, 0, 0}
                };

                c = getopt_long(argc, argv, "h46p:o:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
		case 1024:
			dtls_server_keyfile = strdup(optarg);
			break;

		case 1025:
			dtls_server_certfile = strdup(optarg);
			break;

		case 1026:
			dtls_cafile = strdup(optarg);
			break;

		case 1027:
			dtls_crlfile = strdup(optarg);
			break;

		case 1028:
			dtls_client_keyfile = strdup(optarg);
			break;

		case 1029:
			dtls_client_certfile = strdup(optarg);
			break;

                case 'h':
                        usage();
                        break;

                case 'p':
			if (capwap_cnt % BLOCK_ALLOC == 0) {
				capwap_port = realloc(capwap_port, sizeof(struct capwap_port) * (capwap_cnt + BLOCK_ALLOC));
				memset(&capwap_port[capwap_cnt], 0, sizeof(struct capwap_port) * BLOCK_ALLOC);
			}
                        capwap_port[capwap_cnt].port = strtol(optarg, NULL, 0);
                        if (errno != 0) {
                                fprintf(stderr, "Invalid numeric argument: '%s'\n", optarg);
                                exit(EXIT_FAILURE);
                        }
			capwap_cnt++;
                        break;

		case 'o':
			pcap_fname = strdup(optarg);
			break;

                default:
                        printf("?? getopt returned character code 0%o ??\n", c);
                }
        }

	if (optind != argc - 2) {
		fprintf(stderr, "Expected argument after options\n");
		exit(EXIT_FAILURE);
	}

	printf("Listen = %s, Server = %s\n", argv[optind], argv[optind + 1]);
	ip_to_addr(argv[optind], (struct sockaddr *)&listen_addr);
	ip_to_addr(argv[optind + 1], (struct sockaddr *)&server_addr);

#if defined(DEBUG)
	inet_ntop(server_addr.ss_family, SIN_ADDR_PTR(&server_addr), ipaddr, sizeof(ipaddr));
	debug("CAPWAP server on: %s\n", ipaddr);
#endif

	/* this must be called once in the program */
        gnutls_global_init();

	if (access(dtls_server_keyfile, R_OK) < 0)
		dtls_server_keyfile = dtls_server_certfile;

	gnutls_certificate_allocate_credentials(&x509_server_cred);
	gnutls_certificate_set_x509_trust_file(x509_server_cred, dtls_cafile, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_crl_file(x509_server_cred, dtls_crlfile, GNUTLS_X509_FMT_PEM);

	if (gnutls_certificate_set_x509_key_file(x509_server_cred, dtls_server_certfile, dtls_server_keyfile, GNUTLS_X509_FMT_PEM) < 0) {
		printf("No server certificate or key were found\n");
		exit(EXIT_FAILURE);
	}

	if (access(dtls_client_keyfile, R_OK) < 0)
		dtls_client_keyfile = dtls_client_certfile;

	gnutls_certificate_allocate_credentials(&x509_client_cred);
	gnutls_certificate_set_x509_trust_file(x509_client_cred, dtls_cafile, GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_crl_file(x509_client_cred, dtls_crlfile, GNUTLS_X509_FMT_PEM);

	if (gnutls_certificate_set_x509_key_file(x509_client_cred, dtls_client_certfile, dtls_client_keyfile, GNUTLS_X509_FMT_PEM) < 0) {
		printf("No client certificate or key were found\n");
		exit(EXIT_FAILURE);
	}

        int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LEGACY);
        /* Generate Diffie-Hellman parameters - for use with DHE
         * kx algorithms. When short bit length is used, it might
         * be wise to regenerate parameters often.
         */
        gnutls_dh_params_init(&dh_params);
        gnutls_dh_params_generate2(dh_params, bits);
	gnutls_certificate_set_dh_params(x509_server_cred, dh_params);
	gnutls_certificate_set_dh_params(x509_client_cred, dh_params);

	gnutls_priority_init(&priority_cache,
			     "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE", NULL);
	gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);


	if (pcap_fname) {
		pcap = pcap_open_dead(DLT_RAW, 65535);
		if (strcmp(pcap_fname, "-") == 0)
			dumper = pcap_dump_fopen(pcap, stdout);
		else
			dumper = pcap_dump_open(pcap, pcap_fname);
	}

	if (capwap_cnt == 0) {
		capwap_port = calloc(BLOCK_ALLOC, sizeof(struct capwap_port));
		capwap_port[0].port = 5246;
		capwap_port[1].port = 5247;
		capwap_cnt = 2;
	}

	for (i = 0; i < capwap_cnt; i++)
		bind_capwap(&capwap_port[i]);

	ev_signal_init(&signal_watcher, sigint_cb, SIGINT);
	ev_signal_start(EV_DEFAULT_ &signal_watcher);

	ev_run(EV_DEFAULT_ 0);

	if (dumper)
		pcap_dump_close(dumper);

        return 0;
}
