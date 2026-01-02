
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <time.h>

#include "builder.h"
#include "json_util.h"
#include "utils.h"

// Internet checksum (RFC1071)
static uint16_t ones_comp_sum(const void *buf, int len) {
    const uint8_t *data = buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += ((uint16_t)data[0] << 8);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
} __attribute__((packed));

// Helper to write pcap file (global + per-packet)
int write_pcap(const char *fname, const unsigned char *buf, size_t buflen) {
    FILE *f = fopen(fname, "wb");
    if (!f) return -1;
    // pcap global header (little endian)
    uint32_t magic = 0xa1b2c3d4;
    uint16_t ver_major = 2, ver_minor = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 262144, network = 1; // LINKTYPE_ETHERNET=1
    fwrite(&magic,4,1,f);
    fwrite(&ver_major,2,1,f);
    fwrite(&ver_minor,2,1,f);
    fwrite(&thiszone,4,1,f);
    fwrite(&sigfigs,4,1,f);
    fwrite(&snaplen,4,1,f);
    fwrite(&network,4,1,f);
    // our buffer format: [uint32 n][for each: uint32 len][packet bytes]
    const unsigned char *p = buf;
    if (buflen < 4) { fclose(f); return -1; }
    uint32_t n = ntohl(*(uint32_t*)p);
    p += 4;
    size_t left = buflen - 4;
    for (uint32_t i=0;i<n;i++) {
        if (left < 4) break;
        uint32_t plen = ntohl(*(uint32_t*)p);
        p += 4; left -= 4;
        if (left < plen) break;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint32_t ts_sec = (uint32_t)tv.tv_sec;
        uint32_t ts_usec = (uint32_t)tv.tv_usec;
        fwrite(&ts_sec,4,1,f);
        fwrite(&ts_usec,4,1,f);
        fwrite(&plen,4,1,f);
        fwrite(&plen,4,1,f);
        fwrite(p,1,plen,f);
        p += plen; left -= plen;
    }
    fclose(f);
    return 0;
}

// Encode IP options array (simple support for NOP and timestamp option example)
static unsigned char *encode_ip_options(cJSON *opts, int *out_len) {
    // opts: JSON array of option objects. This function reads common option kinds.
    // If opts is NULL or empty, return NULL.
    if (!opts) { *out_len = 0; return NULL; }
    // We'll build into a temporary buffer
    unsigned char tmp[40]; // max IP options 40 bytes
    int idx = 0;
    cJSON *item = NULL;
    // iterate items (this relies on real cJSON implementation)
    item = cJSON_GetObjectItemCaseSensitive(opts, "0"); // placeholder for stub JSON; real JSON should iterate
    // Real implementation should iterate array; here we return NULL if not array
    if (!cJSON_IsArray(opts)) { *out_len = 0; return NULL; }
    cJSON_ArrayForEach(item, opts) {
        cJSON *kind = cJSON_GetObjectItemCaseSensitive(item, "kind");
        if (!cJSON_IsString(kind)) continue;
        const char *k = kind->valuestring;
        if (strcmp(k, "NOP")==0) {
            tmp[idx++] = 1; // NOP
        } else if (strcmp(k, "EOL")==0) {
            tmp[idx++] = 0; // EOL
            break;
        } else if (strcmp(k, "RR")==0) {
            // Record Route example: type 7, length provided or use minimum 4+4*n
            int length = cJSON_GetObjectItemCaseSensitive(item, "length")->valueint;
            if (length < 4) length = 4;
            if (idx + length > 40) break;
            tmp[idx++] = 7;
            tmp[idx++] = length;
            tmp[idx++] = 0; // pointer
            for (int j=3;j<length;j++) tmp[idx++] = 0;
        } else if (strcmp(k, "TS")==0) {
            // Timestamp option (kind 68)
            int length = cJSON_GetObjectItemCaseSensitive(item, "length")->valueint;
            if (length < 4) length = 4;
            if (idx + length > 40) break;
            tmp[idx++] = 68;
            tmp[idx++] = length;
            tmp[idx++] = 5; // pointer typical
            tmp[idx++] = 0; // oflg/overflow
            for (int j=4;j<length;j++) tmp[idx++] = 0;
        } else {
            // unknown - skip
        }
    }
    // pad to 4-byte alignment with NOPs
    while (idx %4) tmp[idx++] = 1;
    unsigned char *out = malloc(idx);
    memcpy(out, tmp, idx);
    *out_len = idx;
    return out;
}

// Encode TCP options array (support MSS, WS, SACK_PERM, TS, NOP, EOL)
static unsigned char *encode_tcp_options(cJSON *opts, int *out_len) {
    if (!opts) { *out_len = 0; return NULL; }
    unsigned char tmp[40];
    int idx=0;
    if (!cJSON_IsArray(opts)) { *out_len = 0; return NULL; }
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, opts) {
        cJSON *kind = cJSON_GetObjectItemCaseSensitive(item, "kind");
        if (!cJSON_IsString(kind)) continue;
        const char *k = kind->valuestring;
        if (strcmp(k,"NOP")==0) {
            tmp[idx++] = 1;
        } else if (strcmp(k,"EOL")==0) {
            tmp[idx++] = 0;
            break;
        } else if (strcmp(k,"MSS")==0) {
            int val = cJSON_GetObjectItemCaseSensitive(item, "value")->valueint;
            tmp[idx++] = 2; // kind
            tmp[idx++] = 4; // length
            tmp[idx++] = (val >> 8) & 0xff;
            tmp[idx++] = val & 0xff;
        } else if (strcmp(k,"WS")==0) {
            int val = cJSON_GetObjectItemCaseSensitive(item, "value")->valueint;
            tmp[idx++] = 3;
            tmp[idx++] = 3;
            tmp[idx++] = val & 0xff;
        } else if (strcmp(k,"SACK_PERM")==0) {
            tmp[idx++] = 4;
            tmp[idx++] = 2;
        } else if (strcmp(k,"TS")==0) {
            unsigned int tsval = (unsigned int)time(NULL);
            unsigned int tsecr = 0;
            tmp[idx++] = 8;
            tmp[idx++] = 10;
            tmp[idx++] = (tsval >> 24) & 0xff;
            tmp[idx++] = (tsval >> 16) & 0xff;
            tmp[idx++] = (tsval >> 8) & 0xff;
            tmp[idx++] = tsval & 0xff;
            tmp[idx++] = (tsecr >> 24) & 0xff;
            tmp[idx++] = (tsecr >> 16) & 0xff;
            tmp[idx++] = (tsecr >> 8) & 0xff;
            tmp[idx++] = tsecr & 0xff;
        } else {
            // skip unknown
        }
        if (idx > 40) break;
    }
    // pad to 4-byte alignment
    while (idx %4) tmp[idx++] = 1;
    unsigned char *out = malloc(idx);
    memcpy(out, tmp, idx);
    *out_len = idx;
    return out;
}

// Build single IP packet (with possible IP/TCP options encoded)
// Return packet buffer and length via out_buf/out_len
static int build_single_packet(cJSON *config, unsigned char **out_buf, size_t *out_len,
                               unsigned char *l2_dst_mac, int include_l2)
{
    const char *src_ip = json_get_string(config, "layers.ip.fields.src_ip.default", "192.168.0.99");
    const char *dst_ip = json_get_string(config, "layers.ip.fields.dst_ip.default", "192.168.0.100");
    int ttl = json_get_int(config, "layers.ip.fields.ttl.default", 64);
    const char *transport_choice = json_get_string(config, "layers.transport_choice.default", NULL);
    const char *transport = transport_choice && strlen(transport_choice)>0 ? transport_choice : "udp";
    int is_tcp = (strcmp(transport, "tcp")==0);
    const char *pdata = json_get_string(config, "layers.payload.fields.data.default", "Hello, world");
    size_t payload_len = strlen(pdata);
    unsigned char *payload = malloc(payload_len);
    memcpy(payload, pdata, payload_len);

    // options
    cJSON *ip_opts = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(config, "layers")->child, "ip"); // placeholder access
    // Real access: json_get_node_by_path etc. Here we'll fetch using json_get_node_by_path for proper usage
    cJSON *ip_opts_node = json_get_node_by_path(config, "layers.ip.fields.options");
    int ip_opts_len = 0;
    unsigned char *ip_opts_bytes = encode_ip_options(ip_opts_node, &ip_opts_len);

    cJSON *tcp_opts_node = json_get_node_by_path(config, "layers.tcp.fields.options");
    int tcp_opts_len = 0;
    unsigned char *tcp_opts_bytes = NULL;
    if (is_tcp) tcp_opts_bytes = encode_tcp_options(tcp_opts_node, &tcp_opts_len);

    size_t eth_hdr_len = include_l2 ? ETH_HLEN + (json_get_bool(config, "layers.vlan.fields.present.default", 0)?4:0) : 0;
    size_t ip_hdr_len = sizeof(struct iphdr) + ip_opts_len;
    size_t trans_hdr_len = is_tcp ? (sizeof(struct tcphdr) + tcp_opts_len) : sizeof(struct udphdr);
    size_t total_len = eth_hdr_len + ip_hdr_len + trans_hdr_len + payload_len;

    unsigned char *buf = malloc(total_len);
    if (!buf) { free(payload); if (ip_opts_bytes) free(ip_opts_bytes); if (tcp_opts_bytes) free(tcp_opts_bytes); return -1; }
    memset(buf,0,total_len);
    size_t offset = 0;

    if (include_l2) {
        struct ether_header *eth = (struct ether_header*)(buf + offset);
        //if (l2_dst_mac) memcpy(eth->ether_dhost, l2_dst_mac, 6);
        uint8_t dstmac[6];
        const char *dmac = json_get_string(config, "layers.ethernet.fields.dst_mac.default", "ff:ff:ff:ff:ff:ff");
       if (parse_mac(dmac, dstmac) == 0) {
            memcpy(eth->ether_dhost, dstmac, 6);
        } 
        else {
            // 如果解析失败，使用全零
            memset(eth->ether_dhost, l2_dst_mac, 6);
        }
        // src MAC read from config (fallback)
        uint8_t srcmac[6];
        const char *smac = json_get_string(config, "layers.ethernet.fields.src_mac.default", "00:11:22:33:44:55");
        if (parse_mac(smac, srcmac)==0) memcpy(eth->ether_shost, srcmac, 6);
        unsigned int ethertype = 0x0800;
        const char *ethertype_s = json_get_string(config, "layers.ethernet.fields.ethertype.default", "0x0800");
        ethertype = (unsigned int)strtoul(ethertype_s, NULL, 0);
        eth->ether_type = htons((uint16_t)ethertype);
        offset += sizeof(struct ether_header);
        if (json_get_bool(config, "layers.vlan.fields.present.default", 0)) {
            uint16_t tpid = (uint16_t)strtoul(json_get_string(config, "layers.vlan.fields.tpid.default", "0x8100"), NULL, 0);
            uint16_t tci = (uint16_t)strtoul(json_get_string(config, "layers.vlan.fields.tci.default", "0x0001"), NULL, 0);
            uint16_t *p = (uint16_t*)(buf + offset);
            p[0] = htons(tpid);
            p[1] = htons(tci);
            offset += 4;
        }
    }

    // IP header
    struct iphdr *ip = (struct iphdr*)(buf + offset);
    ip->version = 4;
    ip->ihl = (ip_hdr_len)/4;
    int dscp = json_get_int(config, "layers.ip.fields.dscp.default", 0);
    int ecn = json_get_int(config, "layers.ip.fields.ecn.default", 0);
    ip->tos = (dscp << 2) | (ecn & 0x3);
    uint16_t ip_tot_len = (uint16_t)(ip_hdr_len + trans_hdr_len + payload_len);
    ip->tot_len = htons(ip_tot_len);
    int identification = json_get_int(config, "layers.ip.fields.identification.default", 0);
    ip->id = htons((uint16_t)identification);
    int df = json_get_bool(config, "layers.ip.fields.flags.default.DF", 0);
    int mf = json_get_bool(config, "layers.ip.fields.flags.default.MF", 0);
    int frag_off = json_get_int(config, "layers.ip.fields.fragment_offset.default", 0);
    uint16_t frag = ((df?0x4000:0) | (mf?0x2000:0) | (frag_off & 0x1fff));
    ip->frag_off = htons(frag);
    ip->ttl = (uint8_t)ttl;
    ip->protocol = is_tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    // copy ip options if any
    if (ip_opts_len) memcpy(buf + offset + sizeof(struct iphdr), ip_opts_bytes, ip_opts_len);
    // ip checksum
    ip->check = ones_comp_sum(ip, ip_hdr_len);
    offset += ip_hdr_len;

    if (!is_tcp) {
        struct udphdr *uh = (struct udphdr*)(buf + offset);
        int sport = json_get_int(config, "layers.udp.fields.src_port.default", 11111);
        int dport = json_get_int(config, "layers.udp.fields.dst_port.default", 1111);
        uh->source = htons((uint16_t)sport);
        uh->dest = htons((uint16_t)dport);
        uh->len = htons((uint16_t)(trans_hdr_len + payload_len));
        uh->check = 0;
        // pseudo header for checksum
        struct pseudo_hdr ph;
        ph.src = ip->saddr; ph.dst = ip->daddr; ph.zero = 0; ph.proto = IPPROTO_UDP;
        ph.len = htons((uint16_t)(trans_hdr_len + payload_len));
        size_t pcnt = sizeof(ph) + trans_hdr_len + payload_len;
        unsigned char *pbuf = malloc(pcnt);
        memcpy(pbuf, &ph, sizeof(ph));
        memcpy(pbuf + sizeof(ph), uh, trans_hdr_len);
        memcpy(pbuf + sizeof(ph) + trans_hdr_len, payload, payload_len);
        uh->check = ones_comp_sum(pbuf, (int)pcnt);
        free(pbuf);
    } else {
        struct tcphdr *th = (struct tcphdr*)(buf + offset);
        int sport = json_get_int(config, "layers.tcp.fields.src_port.default", 12345);
        int dport = json_get_int(config, "layers.tcp.fields.dst_port.default", 80);
        th->source = htons((uint16_t)sport);
        th->dest = htons((uint16_t)dport);
        th->seq = htonl((uint32_t)json_get_int(config, "layers.tcp.fields.seq_num.default", 0));
        th->ack_seq = htonl((uint32_t)json_get_int(config, "layers.tcp.fields.ack_num.default", 0));
        th->doff = (uint8_t)((sizeof(struct tcphdr) + tcp_opts_len)/4);
        th->syn = json_get_bool(config, "layers.tcp.fields.flags.default.SYN", 1);
        th->ack = json_get_bool(config, "layers.tcp.fields.flags.default.ACK", 0);
        th->fin = json_get_bool(config, "layers.tcp.fields.flags.default.FIN", 0);
        th->rst = json_get_bool(config, "layers.tcp.fields.flags.default.RST", 0);
        th->psh = json_get_bool(config, "layers.tcp.fields.flags.default.PSH", 0);
        th->urg = json_get_bool(config, "layers.tcp.fields.flags.default.URG", 0);
        th->window = htons((uint16_t)json_get_int(config, "layers.tcp.fields.window.default", 65535));
        th->check = 0;
        th->urg_ptr = 0;
        // copy tcp options if any
        if (tcp_opts_len) memcpy((unsigned char*)th + sizeof(struct tcphdr), tcp_opts_bytes, tcp_opts_len);
        // tcp checksum with pseudo header
        struct pseudo_hdr ph;
        ph.src = ip->saddr; ph.dst = ip->daddr; ph.zero = 0; ph.proto = IPPROTO_TCP;
        ph.len = htons((uint16_t)(trans_hdr_len + payload_len));
        size_t pcnt = sizeof(ph) + trans_hdr_len + payload_len;
        unsigned char *pbuf = malloc(pcnt);
        memcpy(pbuf, &ph, sizeof(ph));
        memcpy(pbuf + sizeof(ph), th, trans_hdr_len);
        memcpy(pbuf + sizeof(ph) + trans_hdr_len, payload, payload_len);
        th->check = ones_comp_sum(pbuf, (int)pcnt);
        free(pbuf);
    }

    // payload copy
    memcpy(buf + offset + trans_hdr_len, payload, payload_len);

    if (ip_opts_bytes) free(ip_opts_bytes);
    if (tcp_opts_bytes) free(tcp_opts_bytes);
    free(payload);

    *out_buf = buf;
    *out_len = total_len;
    return 0;
}

// Build fragments: create multiple IP fragments and pack into special buffer:
// Format: [uint32 n][for i: uint32 len_i][packet_i bytes]
int builder_build_packet(cJSON *config, unsigned char **out_buf, size_t *out_len) {
    int auto_frag = json_get_bool(config, "layers.fragment.fields.auto_fragment.default", 0);
    int mtu = json_get_int(config, "layers.fragment.fields.mtu.default", 1500);
    const char *backend = json_get_string(config, "layers.send.fields.backend.default", "af_inet");
    int include_l2 = (strcmp(backend, "af_packet")==0);

    // First build a single full packet (no fragmentation) to know header sizes
    unsigned char *single = NULL;
    size_t single_len = 0;
    if (build_single_packet(config, &single, &single_len, NULL, include_l2) != 0) return -1;

    if (!auto_frag) {
        // pack as single-packet format with n=1
        uint32_t n = htonl(1);
        uint32_t plen = htonl((uint32_t)single_len);
        size_t total = 4 + 4 + single_len;
        unsigned char *out = malloc(total);
        memcpy(out, &n, 4);
        memcpy(out+4, &plen, 4);
        memcpy(out+8, single, single_len);
        free(single);
        *out_buf = out;
        *out_len = total;
        return 0;
    }

    // auto fragmentation: split payload into fragments considering IP header length and transport header
    // We'll read IP header info from single packet to compute offsets
    size_t ip_offset = include_l2 ? ETH_HLEN + (json_get_bool(config, "layers.vlan.fields.present.default",0)?4:0) : 0;
    struct iphdr *ip = (struct iphdr*)(single + ip_offset);
    int ip_hdr_len = ip->ihl * 4;
    int l4_proto = ip->protocol;
    size_t l4_hdr_offset = ip_offset + ip_hdr_len;
    size_t l4_hdr_len = (l4_proto==IPPROTO_TCP) ? ( (single[l4_hdr_offset + 12] >> 4) * 4 ) : sizeof(struct udphdr);
    size_t payload_offset = l4_hdr_offset + l4_hdr_len;
    size_t full_payload_len = single_len - payload_offset;

    // compute fragment payload size per fragment: must be multiple of 8 bytes for all but last
    int header_overhead = ip_hdr_len + l4_hdr_len;
    int max_payload_per_fragment = mtu - (include_l2 ? ETH_HLEN : 0) - header_overhead;
    if (max_payload_per_fragment <= 0) { free(single); return -1; }
    int frag_payload_unit = (max_payload_per_fragment / 8) * 8; // force 8-byte multiple
    if (frag_payload_unit <= 0) frag_payload_unit = max_payload_per_fragment; // fallback

    // number of fragments
    int nfrags = (full_payload_len + frag_payload_unit -1)/frag_payload_unit;
    // build each fragment packet
    unsigned char **frags = malloc(sizeof(unsigned char*) * nfrags);
    size_t *frags_len = malloc(sizeof(size_t) * nfrags);
    for (int i=0;i<nfrags;i++) {
        int off = i * frag_payload_unit;
        int this_payload = (int) ( (full_payload_len - off) > frag_payload_unit ? frag_payload_unit : (full_payload_len - off) );
        // allocate packet buffer for this fragment: L2 + IP hdr + l4 header (only in first fragment for some protocols?) + fragment payload
        size_t pkt_len = (include_l2 ? ETH_HLEN + (json_get_bool(config, "layers.vlan.fields.present.default",0)?4:0) : 0) + ip_hdr_len + l4_hdr_len + this_payload;
        unsigned char *pkt = malloc(pkt_len);
        memset(pkt,0,pkt_len);
        // copy L2 if present
        if (include_l2) {
            memcpy(pkt, single, (include_l2?ETH_HLEN:0) + (json_get_bool(config, "layers.vlan.fields.present.default",0)?4:0));
        }
        // build ip header: copy base ip header then adjust flags/offset/total length/checksum
        struct iphdr *newip = (struct iphdr*)(pkt + (include_l2?ETH_HLEN + (json_get_bool(config, "layers.vlan.fields.present.default",0)?4:0) : 0));
        memcpy(newip, ip, ip_hdr_len);
        newip->tos = ip->tos;
        newip->ttl = ip->ttl;
        newip->protocol = ip->protocol;
        // identification keep same
        // fragment offset in units of 8 bytes
        int mf_flag = (i == nfrags-1) ? 0 : 1;
        uint16_t frag_off_field = ((mf_flag?0x2000:0) | ((off/8) & 0x1fff));
        newip->frag_off = htons(frag_off_field);
        uint16_t totlen = htons((uint16_t)(ip_hdr_len + l4_hdr_len + this_payload));
        newip->tot_len = totlen;
        newip->check = 0;
        newip->check = ones_comp_sum(newip, ip_hdr_len);
        // copy l4 header: for UDP, all fragments except first may not include UDP header according to RFC? 
        // For typical fragmentation, transport header present only in first fragment; subsequent fragments contain only data.
        if (i==0) {
            memcpy((unsigned char*)newip + ip_hdr_len, single + l4_hdr_offset, l4_hdr_len);
            // copy payload part
            memcpy((unsigned char*)newip + ip_hdr_len + l4_hdr_len, single + payload_offset + off, this_payload);
            // recompute udp/tcp checksum for first fragment if needed (for UDP zeroing checksum may be acceptable)
            if (l4_proto == IPPROTO_UDP) {
                struct udphdr *uh = (struct udphdr*)((unsigned char*)newip + ip_hdr_len);
                uh->len = htons((uint16_t)(l4_hdr_len + this_payload));
                // compute udp checksum
                struct pseudo_hdr ph;
                ph.src = newip->saddr; ph.dst = newip->daddr; ph.zero = 0; ph.proto = IPPROTO_UDP; ph.len = uh->len;
                size_t pcnt = sizeof(ph) + ntohs(uh->len);
                unsigned char *pbuf = malloc(pcnt);
                memcpy(pbuf, &ph, sizeof(ph));
                memcpy(pbuf + sizeof(ph), uh, l4_hdr_len);
                memcpy(pbuf + sizeof(ph) + l4_hdr_len, (unsigned char*)newip + ip_hdr_len + l4_hdr_len, this_payload);
                uh->check = ones_comp_sum(pbuf, (int)pcnt);
                free(pbuf);
            } else if (l4_proto == IPPROTO_TCP) {
                struct tcphdr *th = (struct tcphdr*)((unsigned char*)newip + ip_hdr_len);
                size_t pcnt = sizeof(struct pseudo_hdr) + l4_hdr_len + this_payload;
                struct pseudo_hdr ph; ph.src = newip->saddr; ph.dst = newip->daddr; ph.zero = 0; ph.proto = IPPROTO_TCP; ph.len = htons((uint16_t)(l4_hdr_len + this_payload));
                unsigned char *pbuf = malloc(pcnt);
                memcpy(pbuf, &ph, sizeof(ph));
                memcpy(pbuf + sizeof(ph), th, l4_hdr_len);
                memcpy(pbuf + sizeof(ph) + l4_hdr_len, (unsigned char*)newip + ip_hdr_len + l4_hdr_len, this_payload);
                th->check = ones_comp_sum(pbuf, (int)pcnt);
                free(pbuf);
            }
        } else {
            // copy payload fragment (no l4 header)
            memcpy((unsigned char*)newip + ip_hdr_len, single + payload_offset + off, this_payload);
            // No transport checksum recalculation for non-first fragments (they don't carry transport header)
        }
        frags[i] = pkt;
        frags_len[i] = pkt_len;
    }

    // pack into special buffer
    uint32_t n_net = htonl((uint32_t)nfrags);
    size_t total_out = 4;
    for (int i=0;i<nfrags;i++) total_out += 4 + frags_len[i];
    unsigned char *out = malloc(total_out);
    unsigned char *p = out;
    memcpy(p, &n_net, 4); p += 4;
    for (int i=0;i<nfrags;i++) {
        uint32_t l = htonl((uint32_t)frags_len[i]);
        memcpy(p, &l, 4); p += 4;
        memcpy(p, frags[i], frags_len[i]); p += frags_len[i];
        free(frags[i]);
    }
    free(frags); free(frags_len);
    free(single);
    *out_buf = out;
    *out_len = total_out;
    return 0;
}
