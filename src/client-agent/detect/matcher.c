#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rule.h"
#include "shared.h"

static inline int condition_matcher(const char* condition)
{
    for (int i = 0; i < num_matchers; i++)
    {
        if (strcmp(DETECT_MATCH_STR[i], condition) == 0)
        {
            return i;
        }
    }
    return -1;
}

static int matcher(char* message, detect_rule_condition_t* rule_condition)
{

    if (rule_condition == NULL || rule_condition->string == NULL)
    {
        merror("NULL condition");
        return -1;
    }
    else if (rule_condition->matcher >= num_matchers || rule_condition->matcher < 0)
    {
        merror("Invalid matcher");
        return -1;
    }

    regex_t regex;
    switch (rule_condition->matcher)
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
        {
            if (regcomp(&regex, rule_condition->string, 0) != 0)
            {
                merror("Invalid regex");
                return -1;
            }
            if (regexec(&regex, message, 0, NULL, 0) == 0)
            {
                return 1;
            }
            break;
        }
        default: merror("Invalid matcher"); return -1;
    }
    return 0;
}

int apply_rule(detect_rule_t* rule, const char* message)
{

    detect_rule_condition_t* condition_iter = rule->conditions[0];
    for (int i = 0; condition_iter != NULL; i++)
    {
        if (matcher(message, condition_iter) == 1)
        {
            return 1;
        }
        condition_iter = rule->conditions[i];
    }
    return -1;
}