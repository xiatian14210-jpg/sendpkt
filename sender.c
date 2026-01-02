
#define _GNU_SOURCE
#include "sender.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>


#include "json_util.h"
#include "utils.h"

// helper to parse our special buffer and send each packet
static int send_buffer_fragments_af_packet(int sock, const unsigned char *buf, size_t buflen, const char *iface) {
    if (buflen < 4) return -1;
    const unsigned char *p = buf;
    uint32_t n = ntohl(*(uint32_t*)p); p += 4; buflen -= 4;
    // prepare sockaddr_ll
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) { perror("if_nametoindex"); return -1; }
    struct sockaddr_ll addr;
    memset(&addr,0,sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    for (uint32_t i=0;i<n;i++) {
        if (buflen < 4) return -1;
        uint32_t plen = ntohl(*(uint32_t*)p); p += 4; buflen -= 4;
        if (buflen < plen) return -1;
        // fill destination mac from packet first 6 bytes
        memcpy(addr.sll_addr, p, 6);
        ssize_t sent = sendto(sock, p, plen, 0, (struct sockaddr*)&addr, sizeof(addr));
        if (sent < 0) { perror("sendto AF_PACKET"); return -1; }
        p += plen; buflen -= plen;
    }
    return 0;
}

static int send_buffer_fragments_af_inet(int sock, const unsigned char *buf, size_t buflen) {
    if (buflen < 4) return -1;
    const unsigned char *p = buf;
    uint32_t n = ntohl(*(uint32_t*)p); p += 4; buflen -= 4;
    for (uint32_t i=0;i<n;i++) {
        if (buflen < 4) return -1;
        uint32_t plen = ntohl(*(uint32_t*)p); p += 4; buflen -= 4;
        if (buflen < plen) return -1;
        // ip header starts at offset 0 for AF_INET buffer (we assume builder wrote IP at offset 0)
        struct iphdr *ip = (struct iphdr*)p;
        struct sockaddr_in sin; memset(&sin,0,sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = ip->daddr;
        ssize_t sent = sendto(sock, p + 0, plen, 0, (struct sockaddr*)&sin, sizeof(sin));
        if (sent < 0) { perror("sendto AF_INET"); return -1; }
        p += plen; buflen -= plen;
    }
    return 0;
}

int sender_send(const unsigned char *pkt, size_t pkt_len, cJSON *config) {
    const char *backend = json_get_string(config, "layers.send.fields.backend.default", "af_inet");
    int dry = json_get_bool(config, "layers.send.fields.dry_run.default", 0);
    if (dry) {
        // write pcap to file for inspection
        const char *fname = "sendpkt_out.pcap";
        int rc = write_pcap(fname, pkt, pkt_len);
        if (rc==0) printf("Wrote pcap: %s\n", fname);
        else printf("Failed to write pcap\n");
        return 0;
    }
    if (strcmp(backend, "af_packet")==0) {
        const char *iface = json_get_string(config, "layers.send.fields.iface.default", json_get_string(config, "iface", "eth0"));
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) { perror("socket AF_PACKET"); return -1; }
        int rc = send_buffer_fragments_af_packet(sock, pkt, pkt_len, iface);
        close(sock);
        return rc;
    } else {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) { perror("socket AF_INET RAW"); return -1; }
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt IP_HDRINCL");
            close(sock);
            return -1;
        }
        int rc = send_buffer_fragments_af_inet(sock, pkt, pkt_len);
        close(sock);
        return rc;
    }
}
