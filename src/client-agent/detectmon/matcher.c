#include <assert.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detect.h"
#include "rule.h"

static inline int condition_matcher(char* condition)
{
    for (int i = 0; i < num_matchers; i++)
    {
        if (strcmp(match_rule_str[i], condition) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int matcher(char* message, detect_rule_condition_t* rule_condition)
{
    int match = condition_matcher(rule_condition->matcher);
    if (match == -1)
    {
        m2error("Invalid matcher");
        return -1;
    }
    switch (match)
    {
        case STARTSWITH:
            if (strncmp(message, rule_condition->string, strlen(rule_condition->string)) == 0)
            {
                return 1;
            }
            break;
        case ENDSWITH:
            if (strcmp(message + strlen(message) - strlen(rule_condition->string), rule_condition->string) == 0)
            {
                return 1;
            }
            break;
        case CONTAINS:
            if (strstr(message, rule_condition->string) != NULL)
            {
                return 1;
            }
            break;
        case REGEX:
            regex_t regex;
            if (regcomp(&regex, rule_condition->string, 0) != 0)
            {
                m2error("Invalid regex");
                return -1;
            }
            if (regexec(&regex, message, 0, NULL, 0) == 0)
            {
                return 1;
            }
            break;
        default: m2error("Invalid matcher"); return -1;
    }
    return 0;
}

/**
 * @brief Apply a rule to a message
 *
 */
int apply_rule(detect_rule_t* rule, char* message)
{
    assert(rule != NULL);

    detect_rule_condition_t* condition_iter = rule->conditions[0];
    for (int i = 0; condition_iter != NULL; i++)
    {
        if (matcher(message, condition_iter) == 1)
        {
            return 1;
        }
        condition_iter = rule->conditions[i];
    }
}