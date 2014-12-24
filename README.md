capwap-mitm - CAPWAP DTLS MITM (Man-In-The-Middle) Proxy
========================================================

This is DTLS MITM proxy for CAPWAP (RFC 5415). It can be used to decrypt and
capture (in pcap format) encrypted CAPWAP traffic.

It's main purpose is for development, debugging and reverse engineering of
CAPWAP sessions. It has no support for modifying the control or payload
traffic.

Building
--------

Requirements:
 * autoconf
 * automake
 * shtool (http://www.gnu.org/software/shtool/)
 * gnutls (http://gnutls.org/)
 * libev (http://software.schmorp.de/pkg/libev.html)
 * libpcap (http://www.tcpdump.org/)

Under Debian/Ubuntu those dependencies should be available with:

    apt-get install automake autoconf shtool libgnutls-dev libev-dev libpcap-dev

Rebuild configure and configure with:

    ./autogen.sh
    ./configure

Running
-------

Put CAPWAP client and server certificates into ./certs or specify them on the
command line (see `capwap-mitm -h`). By default cacerts.pem, client.pem,
client.key, server.pem and server.key are expected. Certificates and keys can
also be combined into a single file, then client.pem and server.pem should
be used.

Run with:

    src/capwap-mitm -o mitm.pcap <CAPWAP Server> <Local IP>

for example:

    src/capwap-mitm -o mitm.pcap 192.168.13.168 172.28.0.2

By default the proxy listens to port 5246 and 5247.
