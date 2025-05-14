#include "detect.h"
#include "external/cJSON/cJSON.h"
#include "rule.h"
#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

inline static const char* matcher_to_string(match_rule_t matcher)
{
    switch (matcher)
    {
        case STARTSWITH: return strdup("startwith");
        case ENDSWITH: return strdup("endswith");
        case CONTAINS: return strdup("contains");
        case REGEX: return strdup("regex");
        case UNDEFINED_MATCHER:
        default: return "undefined";
    }
}

cJSON* format_buffer2json(cJSON* array, log_buffer_t* log_buffer)
{
    if (!log_buffer || log_buffer->cursor == 0)
        return NULL;

    if (array == NULL)
    {
        array = cJSON_CreateArray();
        if (!array)
        {
            merror("Failed to create JSON array.");
            return NULL;
        }
    }

    size_t entry_len = 0;
    for (size_t read_cursor = 0; read_cursor < log_buffer->cursor;)
    {
        char* entry = &log_buffer->buffer[read_cursor];

        // Find the entry size
        entry_len = strnlen(entry, log_buffer->cursor - read_cursor);
        if (entry_len <= 0 || entry_len > log_buffer->cursor - read_cursor)
        {
            merror("Invalid entry length when constructing context, log buffer: %ld", entry_len);
            break;
        }

        cJSON* json_entry = cJSON_CreateString(entry);
        if (!json_entry)
        {
            merror("Failed to create JSON string.");
            cJSON_Delete(array);
            return NULL;
        }

        // Add the JSON string to the array
        m2debug1("Adding log entry to JSON array: %s", entry);
        cJSON_AddItemToArray(array, json_entry);

        // Move the read cursor to the next log entry
        read_cursor += entry_len + 1;
    }

    return array;
}

cJSON* format_rule2json(detect_rule_t* rule)
{
    if (!rule)
        return NULL;

    cJSON* rule_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(rule_obj, "id", (double)rule->id);
    cJSON_AddNumberToObject(rule_obj, "before", (double)rule->before);
    cJSON_AddNumberToObject(rule_obj, "after", (double)rule->after);
    cJSON_AddStringToObject(rule_obj, "name", rule->name);
    cJSON_AddStringToObject(rule_obj, "description", rule->description);

    // Add conditions
    if (rule->conditions)
    {
        cJSON* conditions_array = cJSON_CreateArray();
        for (int i = 0; rule->conditions[i] != NULL; i++)
        {
            cJSON* condition_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(condition_obj, "pattern", rule->conditions[i]->pattern);
            const char* matcher_str = matcher_to_string(rule->conditions[i]->matcher);
            cJSON_AddStringToObject(condition_obj, "matcher", matcher_str);
            free((char*)matcher_str); // Free the string created by matcher_to_string
            cJSON_AddItemToArray(conditions_array, condition_obj);
        }
        cJSON_AddItemToObject(rule_obj, "conditions", conditions_array);
    }

    // Add extensions
    if (rule->ext)
    {
        cJSON* ext_obj = cJSON_CreateObject();
        for (int i = 0; rule->ext[i] != NULL; i++)
        {
            cJSON_AddStringToObject(ext_obj, rule->ext[i]->field, rule->ext[i]->value);
        }
        cJSON_AddItemToObject(rule_obj, "extensions", ext_obj);
    }

    return rule_obj;
}

char* format_hre_2json(hre_t* hre, cJSON* context_array)
{
    if (!hre)
        return strdup("\"N/A\"");

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "timestamp", (double)hre->timestamp);
    cJSON_AddItemToObject(root, "rule", format_rule2json(hre->rule));
    cJSON_AddStringToObject(root, "trigger", hre->event_trigger);
    if (context_array)
    {
        cJSON_AddItemToObject(root, "context", context_array);
    }
    else if (hre->context)
    {
        cJSON_AddStringToObject(root, "context", hre->context);
    }
    else
    {
        cJSON_AddNullToObject(root, "context");
    }
    cJSON_AddStringToObject(root, "detectmon", DETECT_VERSION);

    char* retval = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return retval;
}