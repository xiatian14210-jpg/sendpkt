#ifndef SENDER_H
#define SENDER_H
#include <stddef.h>
#include "cJSON.h"
int sender_send(const unsigned char *pkt, size_t pkt_len, cJSON *config);
#endif
