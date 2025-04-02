#include "rule.h"
#include <assert.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifndef merror
#define merror(...) fprintf(stderr, __VA_ARGS__)
#endif /* merror */

/* Example rule:
{
    "id": "1",
    "name": "sedexp",
    "description": "Detects changes to udev rules, used by sedexp malware",
    "before": 5,
    "after": 5,
    "conditions": {
        "startswith": "File '/etc/udev/rules.d/"
    },
    "ext": {
        "tag": "linux",
        "mitre": "T1546.017"
    }
}
 */

detect_rule_t* parse_rule(const char* json_string)
{
    cJSON* root = cJSON_Parse(json_string);
    if (!root)
        return NULL;

    detect_rule_t* rule = calloc(1, sizeof(detect_rule_t));
    if (!rule)
    {
        cJSON_Delete(root);
        return NULL;
    }

    // Parse primitive fields
    rule->id = cJSON_GetObjectItem(root, "id")->valueint;
    rule->before = cJSON_GetObjectItem(root, "before")->valueint;
    rule->after = cJSON_GetObjectItem(root, "after")->valueint;

    cJSON* name = cJSON_GetObjectItem(root, "name");
    rule->name = strdup(name->valuestring);

    cJSON* desc = cJSON_GetObjectItem(root, "description");
    rule->description = strdup(desc->valuestring);

    // Parse conditions
    cJSON* conditions = cJSON_GetObjectItem(root, "conditions");
    rule->conditions = calloc(1, sizeof(detect_rule_condition_t*) * (cJSON_GetArraySize(conditions) + 1));

    int cond_idx = 0;
    cJSON* cond_item;
    cJSON_ArrayForEach(cond_item, conditions)
    {
        detect_rule_condition_t* cond = calloc(1, sizeof(detect_rule_condition_t));

        if (strcmp(cond_item->string, "startswith") == 0)
        {
            cond->matcher = STARTSWITH;
        }
        else if (strcmp(cond_item->string, "endswith") == 0)
        {
            cond->matcher = ENDSWITH;
        }
        else if (strcmp(cond_item->string, "contains") == 0)
        {
            cond->matcher = CONTAINS;
        }
        else if (strcmp(cond_item->string, "regex") == 0)
        {
            cond->matcher = REGEX;
        }

        cond->string = strdup(cond_item->valuestring);
        rule->conditions[cond_idx++] = cond;
    }

    // Parse extensions
    cJSON* ext = cJSON_GetObjectItem(root, "ext");
    rule->ext = calloc(1, sizeof(detect_rule_extension_t*) * (cJSON_GetArraySize(ext) + 1));

    int ext_idx = 0;
    cJSON* ext_item;
    cJSON_ArrayForEach(ext_item, ext)
    {
        detect_rule_extension_t* extension = calloc(1, sizeof(detect_rule_extension_t));
        extension->field = strdup(ext_item->string);
        extension->value = strdup(ext_item->valuestring);
        rule->ext[ext_idx++] = extension;
    }

    cJSON_Delete(root);
    return rule;
}

void parse_rules(const char* rule_dir, detect_rule_t** rules)
{
    DIR* dir;
    struct dirent* ent;
    size_t capacity = 32;
    size_t count = 0;

    *rules = calloc(capacity, sizeof(detect_rule_t*));
    if (!*rules)
        return;

    if ((dir = opendir(rule_dir)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            // Check for .json extension
            char* ext = strrchr(ent->d_name, '.');
            if (!ext || strcmp(ext, ".json") != 0)
                continue;

            // Build full path
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", rule_dir, ent->d_name);

            // Open and read file
            FILE* fp = fopen(path, "r");
            if (!fp)
                continue;

            fseek(fp, 0, SEEK_END);
            long len = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            char* json_data = malloc(len + 1);
            fread(json_data, 1, len, fp);
            json_data[len] = '\0';
            fclose(fp);

            // Parse and store rule
            detect_rule_t* rule = parse_rule(json_data);
            free(json_data);

            if (rule)
            {
                // Resize array if needed
                if (count >= capacity - 1)
                {
                    capacity *= 2;
                    *rules = realloc(*rules, capacity * sizeof(detect_rule_t*));
                }
                rules[count++] = rule;
            }
        }
        closedir(dir);

        // Null-terminate array
        rules[count] = NULL;
    }
}

/**
 * @brief free a rule and all its resources
 *
 * @param rule the rule to free
 */
void free_rule(detect_rule_t* rule)
{
    if (!rule)
        return;

    // free name and description
    free(rule->name);
    free(rule->description);

    // Free conditions
    if (rule->conditions)
    {
        for (int i = 0; rule->conditions[i] != NULL; i++)
        {
            free(rule->conditions[i]->string);
            free(rule->conditions[i]);
        }
        free(rule->conditions);
    }

    // Free extensions
    if (rule->ext)
    {
        for (int i = 0; rule->ext[i] != NULL; i++)
        {
            free(rule->ext[i]->field);
            free(rule->ext[i]->value);
            free(rule->ext[i]);
        }
        free(rule->ext);
    }

    free(rule);
}

/**
 * @brief formats a rule into a printable string
 *
 * @param rule the rule to format
 * @return char* formatted string, or NULL on failure
 * caller is responsible for freeing the string
 * @note the string is formatted as follows:
 * "RuleID: %d, Name: %s, Description: %s, Before: %ld, After: %ld"
 */
char* format_rule(detect_rule_t* rule)
{
    if (!rule)
        return NULL;
    // calculate the size of the buffer
    size_t size = sizeof(RULE_INFO) + strlen(rule->name) + strlen(rule->description);
    for (int i = 0; rule->conditions[i] != NULL; i++)
    {
        size += strlen(rule->conditions[i]->string) + 1;
    }

    char* buffer = malloc(size);
    if (!buffer)
        return NULL;

    snprintf(buffer, size, RULE_INFO, rule->id, rule->name, rule->description, rule->before, rule->after);
    return buffer;
}