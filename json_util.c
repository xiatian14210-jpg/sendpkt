#define _GNU_SOURCE
#include "json_util.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

cJSON *json_load_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f,0,SEEK_END);
    long sz = ftell(f);
    fseek(f,0,SEEK_SET);
    char *buf = malloc(sz+1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf,1,sz,f);
    buf[sz]=0;
    fclose(f);
    cJSON *root = cJSON_Parse(buf);
    free(buf);
    return root;
}

int json_save_file(cJSON *root, const char *path) {
    char *s = cJSON_Print(root);
    if (!s) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) { free(s); return -1; }
    fwrite(s,1,strlen(s),f);
    fclose(f);
    free(s);
    return 0;
}

cJSON *json_get_node_by_path(cJSON *root, const char *path) {
    if (!root || !path) return NULL;
    char *tmp = strdup(path);
    char *save = tmp;
    char *tok = NULL;
    cJSON *cur = root;
    tok = strsep(&tmp, ".");
    while (tok && cur) {
        cur = cJSON_GetObjectItemCaseSensitive(cur, tok);
        tok = strsep(&tmp, ".");
    }
    free(save);
    return cur;
}

const char *json_get_string(cJSON *root, const char *path, const char *def) {
    cJSON *n = json_get_node_by_path(root, path);
    if (n && cJSON_IsString(n)) return n->valuestring;
    return def;
}

int json_get_int(cJSON *root, const char *path, int def) {
    cJSON *n = json_get_node_by_path(root, path);
    if (n && cJSON_IsNumber(n)) return n->valueint;
    return def;
}

double json_get_double(cJSON *root, const char *path, double def) {
    cJSON *n = json_get_node_by_path(root, path);
    if (n && cJSON_IsNumber(n)) return n->valuedouble;
    return def;
}

int json_get_bool(cJSON *root, const char *path, int def) {
    cJSON *n = json_get_node_by_path(root, path);
    if (n && cJSON_IsBool(n)) return cJSON_IsTrue(n);
    return def;
}

int json_set_value_by_path(cJSON *root, const char *path, const char *value) {
    if (!root || !path || !value) return -1;

    // clone path so we can modify it
    char *tmp = strdup(path);
    if (!tmp) return -1;

    // find last dot to split parent path and key
    char *last_dot = strrchr(tmp, '.');
    char *parent_path = NULL;
    char *key = NULL;
    cJSON *parent = NULL;

    if (last_dot) {
        *last_dot = '\0';
        parent_path = tmp;
        key = last_dot + 1;
        parent = json_get_node_by_path(root, parent_path);
    } else {
        // no dot -> parent is root, key is entire path
        parent = root;
        key = tmp;
    }

    if (!parent) {
        free(tmp);
        return -1;
    }

    // find the target node under parent
    cJSON *node = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!node) {
        // target key not found
        free(tmp);
        return -1;
    }

    // if it's a string, set value in-place
    if (cJSON_IsString(node)) {
        cJSON_SetValuestring(node, value);
        free(tmp);
        return 0;
    }

    // if it's a number, replace with new number node
    if (cJSON_IsNumber(node)) {
        double v = atof(value);
        cJSON *num = cJSON_CreateNumber(v);
        if (!num) { free(tmp); return -1; }
        cJSON_ReplaceItemInObject(parent, key, num);
        free(tmp);
        return 0;
    }

    // if it's a bool, replace with true/false node
    if (cJSON_IsBool(node)) {
        cJSON *b = NULL;
        if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0) b = cJSON_CreateTrue();
        else b = cJSON_CreateFalse();
        if (!b) { free(tmp); return -1; }
        cJSON_ReplaceItemInObject(parent, key, b);
        free(tmp);
        return 0;
    }

    // fallback: replace whatever it is with a string node
    cJSON *s = cJSON_CreateString(value);
    if (!s) { free(tmp); return -1; }
    cJSON_ReplaceItemInObject(parent, key, s);
    free(tmp);
    return 0;
}
