#ifndef JSON_UTIL_H
#define JSON_UTIL_H
#include "cJSON.h"

cJSON *json_load_file(const char *path);
int json_save_file(cJSON *root, const char *path);
cJSON *json_get_node_by_path(cJSON *root, const char *path);
const char *json_get_string(cJSON *root, const char *path, const char *def);
int json_get_int(cJSON *root, const char *path, int def);
double json_get_double(cJSON *root, const char *path, double def);
int json_get_bool(cJSON *root, const char *path, int def);
int json_set_value_by_path(cJSON *root, const char *path, const char *value);

#endif
