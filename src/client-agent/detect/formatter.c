#include "detect.h"
#include "rule.h"
#include "shared.h"
#include <cjson/cJSON.h>
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

cJSON* format_buffer2json(cJSON* array, log_buffer_t* buffer)
{
    if (!buffer || buffer->cursor == 0)
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

    size_t cursor_buffer = 0;
    for (size_t entry_len = 0; cursor_buffer < buffer->cursor; cursor_buffer += entry_len)
    {
        // Find the entry size
        entry_len = strnlen(buffer->buffer + cursor_buffer, buffer->cursor - cursor_buffer);
        if (entry_len == 0)
        {
            break;
        }

        // Create a JSON string for the entry
        char* entry = strndup(buffer->buffer + cursor_buffer, entry_len);
        if (!entry)
        {
            merror("Failed to allocate memory for JSON entry.");
            cJSON_Delete(array);
            return NULL;
        }

        cJSON* json_entry = cJSON_CreateString(entry);
        free(entry);

        if (!json_entry)
        {
            merror("Failed to create JSON string.");
            cJSON_Delete(array);
            return NULL;
        }

        // Add the JSON string to the array
        cJSON_AddItemToArray(array, json_entry);
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
            cJSON_AddStringToObject(condition_obj, "matcher", matcher_to_string(rule->conditions[i]->matcher));
            cJSON_AddItemToArray(conditions_array, condition_obj);
        }
        cJSON_AddItemToObject(rule_obj, "conditions", conditions_array);
    }

    // Add extensions
    if (rule->ext)
    {
        cJSON* extensions_array = cJSON_CreateArray();
        for (int i = 0; rule->ext[i] != NULL; i++)
        {
            cJSON* ext_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(ext_obj, "field", rule->ext[i]->field);
            cJSON_AddStringToObject(ext_obj, "value", rule->ext[i]->value);
            cJSON_AddItemToArray(extensions_array, ext_obj);
        }
        cJSON_AddItemToObject(rule_obj, "extensions", extensions_array);
    }

    return rule_obj;
}

char* format_hre_2json(hre_t* hre, cJSON* context_array)
{
    if (!hre)
        return strdup("\"N/A\"");

    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "timestamp", (double)hre->timestamp);
    cJSON_AddStringToObject(root, "trigger", hre->event_trigger);
    cJSON_AddItemToObject(root, "rule", format_rule2json(hre->rule));
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

    char* retval = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return retval;
}