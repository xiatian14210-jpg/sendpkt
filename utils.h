#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <stddef.h>   
int parse_mac(const char *s, uint8_t mac[6]);
void hexdump(const unsigned char *buf, size_t len);
char *str_trim(char *s);
#endif
