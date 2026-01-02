#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "json_util.h"
#include "builder.h"
#include "sender.h"
#include "utils.h"

#define MAXLINE 4096

static char *str_trim_inplace(char *s) {
    char *start = s;
    while(*start && (*start==' '||*start=='\t'||*start=='\r'||*start=='\n')) start++;
    if (start != s) memmove(s, start, strlen(start)+1);
    size_t len = strlen(s);
    while (len>0 && (s[len-1]=='\n' || s[len-1]=='\r' || s[len-1]==' ' || s[len-1]=='\t')) { s[len-1]=0; len--; }
    return s;
}

static void prompt_and_fill(cJSON *root) {
    cJSON *prompt_order = cJSON_GetObjectItemCaseSensitive(root, "prompt_order");
    if (!prompt_order) return;
    // This is a simplified placeholder: our cJSON here is a stub, so this function
    // will just demonstrate the intended behavior when full cJSON is used.
    printf("Interactive prompt will run (requires real cJSON implementation).\n");
    printf("You can later use 'edit' command to re-run interactive prompts.\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <preset.json>\n", argv[0]);
        return 1;
    }
    cJSON *root = json_load_file(argv[1]);
    if (!root) { fprintf(stderr, "Failed to parse preset (ensure cJSON is real and preset file exists)\n"); return 2; }
    printf("Loaded preset: %s\n", json_get_string(root, "meta.preset_name", "unnamed"));

    // initial prompt: do interactive fill (stub)
    prompt_and_fill(root);

    // REPL
    char line[4096];
    while (1) {
        printf("sendpkt> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        char *cmd = str_trim_inplace(line);
        if (strcmp(cmd, "exit")==0 || strcmp(cmd, "quit")==0) break;
        if (strcmp(cmd, "show")==0) {
            char *s = cJSON_Print(root);
            puts(s);
            free(s);
            continue;
        }
        if (strncmp(cmd, "set ", 4)==0) {
            char *rest = cmd + 4;
            char *sp = strchr(rest, ' ');
            if (!sp) { printf("usage: set <path> <value>\n"); continue; }
            *sp = 0;
            char *path = rest;
            char *val = sp + 1;
            if (json_set_value_by_path(root, path, val) == 0) {
                printf("Set %s = %s\n", path, val);
            } else printf("Failed to set\n");
            continue;
        }
        if (strncmp(cmd, "save ", 5)==0) {
            char *path = cmd + 5;
            if (json_save_file(root, path)==0) printf("Saved to %s\n", path);
            else printf("Save failed\n");
            continue;
        }
        if (strcmp(cmd, "send")==0) {
            unsigned char *pkt = NULL;
            size_t pkt_len = 0;
            if (builder_build_packet(root, &pkt, &pkt_len) != 0) {
                printf("Failed to build packet\n");
                continue;
            }
            int dry_run = json_get_bool(root, "layers.send.fields.dry_run.default", 0);
            if (dry_run) {
                // call sender_send which in the v2 implementation will write pcap on dry-run
                int rc = sender_send(pkt, pkt_len, root);
                if (rc == 0) {
                    printf("Dry-run: wrote pcap file (sendpkt_out.pcap)\n");
                } else {
                    fprintf(stderr, "Dry-run: failed to write pcap (sender_send rc=%d)\n", rc);
                    // fallback: print hex so user still sees the packet
                    printf("Dry-run: packet %zu bytes (hex):\n", pkt_len);
                    for (size_t i=0;i<pkt_len;i++) {
                        printf("%02x", pkt[i]);
                        if ((i+1)%16==0) printf("\n");
                        else if ((i+1)%2==0) printf(" ");
                    }
                    printf("\n");
                }
                free(pkt);
                continue;
            }
            int cnt = json_get_int(root, "layers.send.fields.count.default", 1);
            double interval = json_get_double(root, "layers.send.fields.interval_s.default", 1.0);
            int succ = 0;
            for (int i=0;i<cnt;i++) {
                if (sender_send(pkt, pkt_len, root)==0) succ++;
                if (i != cnt-1) usleep((useconds_t)(interval*1e6));
            }
            printf("Sent %d/%d\n", succ, cnt);
            free(pkt);
            continue;
        }
        if (strcmp(cmd, "edit")==0) {
            prompt_and_fill(root);
            continue;
        }
        printf("Unknown command. Available: show, set <path> <value>, edit, send, save <file>, exit\n");
    }

    cJSON_Delete(root);
    return 0;
}
