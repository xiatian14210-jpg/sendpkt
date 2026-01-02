#include "utils.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

int parse_mac(const char *s, uint8_t mac[6]) {
    if (!s) return -1;
    int vals[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &vals[0],&vals[1],&vals[2],&vals[3],&vals[4],&vals[5]) != 6)
        return -1;
    for (int i=0;i<6;i++) mac[i] = (uint8_t)vals[i];
    return 0;
}

void hexdump(const unsigned char *buf, size_t len) {
    for (size_t i=0;i<len;i++) {
        printf("%02x", buf[i]);
        if ((i+1)%16==0) printf("\n");
        else if ((i+1)%2==0) printf(" ");
    }
    if (len%16) printf("\n");
}

char *str_trim(char *s) {
    char *end;
    while(isspace((unsigned char)*s)) s++;
    if(*s == 0) return s;
    end = s + strlen(s) - 1;
    while(end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}
