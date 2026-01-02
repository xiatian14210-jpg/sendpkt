#ifndef BUILDER_H
#define BUILDER_H
#include "cJSON.h"
int builder_build_packet(cJSON *config, unsigned char **out_buf, size_t *out_len);
int write_pcap(const char *fname, const unsigned char *buf, size_t buflen);
#endif
