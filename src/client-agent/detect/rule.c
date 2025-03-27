#include "rule.h"
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
 * @brief Parse a condition from JSON
 *
 * @param json_condition The JSON object containing the condition
 * @return detect_rule_condition_t** Array of conditions (null-terminated)
 */
detect_rule_condition_t** parse_conditions(cJSON* json_condition)
{
    if (!json_condition || !cJSON_IsObject(json_condition))
    {
        return NULL;
    }

    cJSON* child = NULL;
    detect_rule_condition_t** conditions;
    int count = cJSON_GetArraySize(json_condition);

    // Allocate memory for the conditions array (plus 1 for NULL terminator)
    conditions = (detect_rule_condition_t**)malloc((count + 1) * sizeof(detect_rule_condition_t*));
    if (conditions == NULL)
    {
        PRINT_ERR("Failed to allocate memory\n", NULL);
        return NULL;
    }

    // Initialize to NULL
    for (int i = 0; i <= count; i++)
    {
        conditions[i] = NULL;
    }

    // Parse each condition
    int index = 0;
    child = NULL;
    cJSON_ArrayForEach(child, json_condition)
    {
        const char* matcher_str = child->string;
        const char* value = cJSON_GetStringValue(child);
        if (!matcher_str || !value)
            continue;

        // Find the matcher type
        match_rule_t matcher = num_matchers; // Invalid by default
        for (int i = 0; i < num_matchers; i++)
        {
            if (strcmp(matcher_str, DETECT_MATCH_STR[i]) == 0)
            {
                matcher = (match_rule_t)i;
                break;
            }
        }

        if (matcher == num_matchers)
        {
            PRINT_ERR("Unknown matcher type: %s at %s:%d\n", matcher_str);
            continue;
        }

        // Allocate and set up the condition
        detect_rule_condition_t* condition = (detect_rule_condition_t*)malloc(sizeof(detect_rule_condition_t));
        if (!condition)
        {
            PRINT_ERR("Failed to allocate memory for condition at %s:%d\n");
            continue;
        }

        condition->matcher = matcher;
        condition->string = strdup(value);
        conditions[index++] = condition;
    }

    return conditions;
}

/**
 * @brief Parse extensions from JSON
 *
 * @param json_ext The JSON object containing the extensions
 * @return detect_rule_extension_t** Array of extensions (null-terminated)
 */
static detect_rule_extension_t** parse_extensions(cJSON* json_ext)
{
    if (!json_ext || !cJSON_IsObject(json_ext))
    {
        return NULL;
    }

    // Count the number of extensions
    cJSON* child = NULL;
    detect_rule_extension_t** extensions;
    int count = cJSON_GetArraySize(json_ext);

    // Allocate memory for the extensions array (plus 1 for NULL terminator)
    extensions = (detect_rule_extension_t**)malloc((count + 1) * sizeof(detect_rule_extension_t*));
    if (extensions == NULL)
    {
        PRINT_ERR("Failed to allocate memory for extensions at %s:%d\n");
        return NULL;
    }

    // initialize to NULL
    for (int i = 0; i <= count; i++)
    {
        extensions[i] = NULL;
    }

    // parse each extension
    int index = 0;
    child = NULL;
    cJSON_ArrayForEach(child, json_ext)
    {
        const char* field = child->string;
        if (!field)
            continue;

        detect_rule_extension_t* extension = (detect_rule_extension_t*)malloc(sizeof(detect_rule_extension_t));
        if (!extension)
        {
            PRINT_ERR("Failed to allocate memory for extension at %s:%d\n");
            continue;
        }

        extension->field = strdup(field);

        // Handle different value types
        if (cJSON_IsString(child))
        {
            extension->value = strdup(cJSON_GetStringValue(child));
        }
        else if (cJSON_IsNumber(child))
        {
            double* value = (double*)malloc(sizeof(double));
            *value = child->valuedouble;
            extension->value = value;
        }
        else if (cJSON_IsBool(child))
        {
            int* value = (int*)malloc(sizeof(int));
            *value = cJSON_IsTrue(child);
            extension->value = value;
        }
        else
        {
            // complex type, store the JSON string
            extension->value = cJSON_Print(child);
        }

        extensions[index++] = extension;
    }

    return extensions;
}

/**
 * @brief Parse a rule from JSON
 *
 * @param json_string The JSON string to parse
 * @return detect_rule_t* The parsed rule or NULL on failure
 */
detect_rule_t* parse_rule(const char* json_string)
{
    if (!json_string)
    {
        PRINT_ERR("NULL JSON string at %s:%d\n");
        return NULL;
    }

    cJSON* json = cJSON_Parse(json_string);
    if (!json)
    {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr)
        {
            PRINT_ERR("Error parsing JSON before: %s at %s:%d\n", error_ptr);
        }
        return NULL;
    }

    detect_rule_t* rule = (detect_rule_t*)malloc(sizeof(detect_rule_t));
    if (!rule)
    {
        PRINT_ERR("Failed to allocate memory for rule at %s:%d\n");
        cJSON_Delete(json);
        return NULL;
    }

    // Initialize with defaults
    rule->id = -1;
    rule->before = 3;
    rule->after = 3;
    rule->name = NULL;
    rule->description = NULL;
    rule->conditions = NULL;
    rule->ext = NULL;

    // id
    cJSON* id = cJSON_GetObjectItemCaseSensitive(json, "id");
    if (cJSON_IsNumber(id))
    {
        rule->id = id->valueint;
    }

    // rule name
    cJSON* name = cJSON_GetObjectItemCaseSensitive(json, "name");
    if (cJSON_IsString(name) && name->valuestring)
    {
        rule->name = strdup(name->valuestring);
    }

    // description
    cJSON* description = cJSON_GetObjectItemCaseSensitive(json, "description");
    if (cJSON_IsString(description) && description->valuestring)
    {
        rule->description = strdup(description->valuestring);
    }

    // before
    cJSON* before = cJSON_GetObjectItemCaseSensitive(json, "before");
    if (cJSON_IsNumber(before))
    {
        rule->before = before->valueint;
    }

    // after
    cJSON* after = cJSON_GetObjectItemCaseSensitive(json, "after");
    if (cJSON_IsNumber(after))
    {
        rule->after = after->valueint;
    }

    // conditions
    cJSON* conditions = cJSON_GetObjectItemCaseSensitive(json, "conditions");
    if (conditions)
    {
        rule->conditions = parse_conditions(conditions);
    }

    // extensions
    cJSON* ext = cJSON_GetObjectItemCaseSensitive(json, "ext");
    if (ext)
    {
        rule->ext = parse_extensions(ext);
    }

    cJSON_Delete(json);
    return rule;
}

/**
 * @brief Read a file into a string
 *
 * @param filename The name of the file to read
 * @return char* The file contents or NULL on failure
 */
static char* read_file(const char* filename)
{
    FILE* file = fopen(filename, "r");
    if (!file)
    {
        PRINT_ERR("Failed to open file: %s at %s:%d\n", filename);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    char* buffer = (char*)malloc(size + 1);
    if (!buffer)
    {
        PRINT_ERR("Failed to allocate memory for file contents at %s:%d\n");
        fclose(file);
        return NULL;
    }

    // Read file contents
    size_t read_size = fread(buffer, 1, size, file);
    buffer[read_size] = '\0';
    fclose(file);

    return buffer;
}

static void list_files(const char* path)
{
    DIR* dir;
    struct dirent* entry;
    struct stat file_stat;
    char full_path[1024];

    // Open the directory
    if ((dir = opendir(path)) == NULL)
    {
        perror("Error opening directory");
        return;
    }

    printf("Contents of directory '%s':\n", path);

    // Read directory entries
    while ((entry = readdir(dir)) != NULL)
    {
        // Skip "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        // Create full path for each entry
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        // Get file stats
        if (stat(full_path, &file_stat) == -1)
        {
            perror("Error getting file stats");
            continue;
        }

        // Check if it's a file or directory
        if (S_ISDIR(file_stat.st_mode))
        {
            printf("[DIR]  %s\n", entry->d_name);
        }
        else
        {
            printf("[FILE] %s (%ld bytes)\n", entry->d_name, file_stat.st_size);
        }
    }

    // Close the directory
    closedir(dir);
}

/**
 * @brief Parse detection rules from a directory
 *
 * @param rule_dir The directory containing the rules
 * @param rules The array of rules to populate
 */
void parse_rules(const char* rule_dir, detect_rule_t** rules)
{
    assert(rule_dir != NULL);
    assert(rules != NULL);

    // iterate files in rule directory
    DIR* dir;
    struct dirent* entry;
    char full_path[1024];

    if ((dir = opendir(rule_dir)) == NULL)
    {
        perror("Error opening directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", rule_dir, entry->d_name);

        // Read file contents
        char* contents = read_file(full_path);
        if (!contents)
        {
            continue;
        }

        // parse the rule
        detect_rule_t* rule = parse_rule(contents);
        if (rule)
        {
            // add the rule to the list
            for (int i = 0; rules[i] != NULL; i++)
            {
                if (rules[i]->id == -1)
                {
                    free_rule(rules[i]);
                    rules[i] = rule;
                    break;
                }
            }
        }

        free(contents);
    }

    closedir(dir);
}

char* format_rule(detect_rule_t* rule)
{
    if (!rule)
        return NULL;

    return NULL;
}