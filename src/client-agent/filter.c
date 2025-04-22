#include "detect/rule.h"

#include "filter.h"
#include "shared.h"
#include <stdlib.h>
#include <string.h>

static detect_rule_t* rules[FILTER_RULE_MAX] = {NULL}; // Array of rules

detect_rule_t** filter_init(const char* rule_dir)
{

    // default rule directory
    if (rule_dir == NULL)
    {
        rule_dir = FILTER_RULE_DIRECTORY;
    }

    // Initialize rules array
    for (int i = 0; i < FILTER_RULE_MAX; i++)
    {
        rules[i] = NULL;
    }

    // Parse rules from the directory
    detect_rule_t** rules = NULL;
    parse_rules(rule_dir, rules);
    if (rules == NULL)
    {
        merror("Failed to parse rules from directory: %s", rule_dir);
        return NULL;
    }
    return rules;
}

void filter_free(detect_rule_t** rules)
{
    if (rules == NULL)
    {
        merror("Invalid rules array");
        return;
    }

    // Free each rule
    for (int i = 0; rules[i] != NULL; i++)
    {
        free_rule(rules[i]);
        rules[i] = NULL;
    }
}

/**
 * @brief Check if a log message matches any filter rules.
 *
 * @param rules th array of filter rules
 * @param message the log message to check
 * @param length the length of the log message
 * @return int t
 he ID of the matching rule, or 0 if no match is found.
 */
int filter_log_check(detect_rule_t** rules, const char* message, size_t length)
{
    if (rules == NULL)
    {
        mdebug1("No filter rules loaded");
        return 0;
    }
    else if (message == NULL || length <= 0)
    {
        merror("Invalid arguments");
        return -1;
    }

    for (int i = 0; rules[i] != NULL; i++)
    {
        detect_rule_t* rule = rules[i];
        if (apply_rule(rule, message, length) == 0)
        {
            mdebug1("Filter rule matched: %s, dropping\n", rule->name);
            return rule->id; // Rule matched
        }
    }

    return 0; // No rule matched
}