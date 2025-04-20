#include "rule.h"
#include "detect.h"
#include "shared.h"
#include <assert.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

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

// string representation of the matchers
static const char* DETECT_MATCH_STR[] = {"startswith", "endswith", "contains", "regex"};

static inline int condition_matcher(const char* condition, size_t length)
{
    if (condition == NULL || length <= 0)
    {
        merror("Invalid condition");
        return -1;
    }

    for (int i = 0; i < num_matchers; i++)
    {
        if (strncmp(DETECT_MATCH_STR[i], condition, length) == 0)
        {
            return i;
        }
    }
    return -1;
}

detect_rule_t* parse_rule(const char* json_string)
{
    cJSON* root = cJSON_Parse(json_string);
    if (!root)
    {
        merror("Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    detect_rule_t* rule = malloc(sizeof(detect_rule_t));
    if (!rule)
    {
        cJSON_Delete(root);
        return NULL;
    }

    /* Parse primitive fields */
    cJSON* tmp;
    rule->id = cJSON_GetObjectItem(root, "id")->valueint;

    tmp = cJSON_GetObjectItem(root, "before");
    rule->before = tmp->valueint ? (cJSON_IsNumber(tmp)) : RULE_DEFAULT_BEFORE;

    tmp = cJSON_GetObjectItem(root, "after");
    rule->after = tmp->valueint ? (cJSON_IsNumber(tmp)) : RULE_DEFAULT_AFTER;

    cJSON* name = cJSON_GetObjectItem(root, "name");
    if (cJSON_IsString(name))
    {
        size_t len = strlen(name->valuestring);
        rule->name = strndup(name->valuestring, len ? len < RULE_MAX_NAME : RULE_MAX_NAME);
    }
    else
    {
        merror("Invalid name type: %d\n", name->type);
        free(rule);
        cJSON_Delete(root);
        return NULL;
    }

    /* Description field, optional */
    if (cJSON_HasObjectItem(root, "description") == 0)
    {
        cJSON* desc = cJSON_GetObjectItem(root, "description");
        rule->description = strdup(desc->valuestring);
    }
    else
    {
        rule->description = NULL;
    }

    /* Parse conditions, optional */
    if (cJSON_HasObjectItem(root, "conditions") == 1)
    {
        cJSON* conditions = cJSON_GetObjectItem(root, "conditions");
        rule->conditions = calloc(cJSON_GetArraySize(conditions) + 1, sizeof(detect_rule_condition_t*));

        int cond_idx = 0;
        cJSON* cond_item;
        cJSON_ArrayForEach(cond_item, conditions)
        {
            if (cond_idx >= RULE_MAX_CONDITIONS)
            {
                mdebug1("Too many conditions, truncating\n");
                break;
            }

            if (cond_item->type != cJSON_String)
            {
                merror("Invalid condition type: %d\n", cond_item->type);
                continue;
            }

            detect_rule_condition_t* cond = calloc(1, sizeof(detect_rule_condition_t));
            if (!cond)
            {
                merror("Failed to allocate memory for condition\n");
                continue;
            }

            cond->matcher = condition_matcher(cond_item->string, strlen(cond_item->string));
            if (cond->matcher == -1)
            {
                merror("Invalid matcher: %s\n", cond_item->string);
                free(cond);
                continue;
            }

            cond->string = strdup(cond_item->valuestring);
            rule->conditions[cond_idx++] = cond;
        }
        // NULL terminate the conditions array
        rule->conditions[cond_idx] = NULL;
    }
    else
    {
        rule->conditions = NULL;
    }

    /* Parse extensions, optional */
    if (cJSON_HasObjectItem(root, "ext") == 1)
    {

        cJSON* ext = cJSON_GetObjectItem(root, "ext");
        rule->ext = calloc(cJSON_GetArraySize(ext) + 1, sizeof(detect_rule_extension_t*));

        int ext_idx = 0;
        cJSON* ext_item;
        cJSON_ArrayForEach(ext_item, ext)
        {
            // safety guard
            if (ext_idx >= RULE_MAX_EXTENSIONS)
            {
                mdebug1("Too many extensions, truncating\n");
                break;
            }
            detect_rule_extension_t* extension = calloc(1, sizeof(detect_rule_extension_t));
            extension->field = strdup(ext_item->string);
            extension->value = strdup(ext_item->valuestring);
            rule->ext[ext_idx++] = extension;
        }
        // NULL terminate the extensions array
        rule->ext[ext_idx] = NULL;
    }
    else
    {
        rule->ext = NULL;
    }

    cJSON_Delete(root);
    return rule;
}

int parse_rules(const char* rule_dir, detect_rule_t** rules)
{
    DIR* dir;
    struct dirent* ent;
    size_t capacity = 32;
    size_t count = 0;

    *rules = calloc(capacity, sizeof(detect_rule_t*));
    if (!*rules)
        return -1;

    if ((dir = opendir(rule_dir)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            // Check for .json extension
            char* ext = strrchr(ent->d_name, '.');
            if (!ext || strncmp(ext, ".json", sizeof(".json")) != 0)
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
        return count;
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

    // TODO: add conditions and extensions to the buffer
    // format the rule into the buffer
    snprintf(buffer, size, RULE_INFO, rule->id, rule->name, rule->description, rule->before, rule->after);
    return buffer;
}