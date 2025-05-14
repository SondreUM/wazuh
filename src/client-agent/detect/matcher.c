#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "rule.h"
#include "shared.h"

static int matcher(detect_rule_condition_t* rule_condition, const char* message, size_t len)
{

    if (rule_condition == NULL || rule_condition->pattern == NULL)
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
            if (strncmp(message, rule_condition->pattern, MIN(len, strlen(rule_condition->pattern))) == 0)
            {
                return 1;
            }
            break;
        case ENDSWITH:
            if (strcmp(message + strlen(message) - strlen(rule_condition->pattern), rule_condition->pattern) == 0)
            {
                return 1;
            }
            break;
        case CONTAINS:
            if (strstr(message, rule_condition->pattern) != NULL)
            {
                return 1;
            }
            break;
        case REGEX:
        {
            if (regcomp(&regex, rule_condition->pattern, 0) != 0)
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

int apply_rule(detect_rule_t* rule, const char* message, size_t len)
{
    if (rule == NULL || message == NULL || len <= 0)
    {
        merror("Invalid arguments to apply_rule");
        return -1;
    }

    if (rule->conditions == NULL)
    {
        mwarn("No conditions to apply");
        return 0;
    }

    detect_rule_condition_t* condition_iter = rule->conditions[0];
    for (int i = 0; condition_iter != NULL; i++)
    {
        // mdebug2("Checking rule %s with mode %d\nPATTERN: %s\nMSG: %s",
        //         rule->name,
        //         condition_iter->matcher,
        //         condition_iter->pattern,
        //         message);
        if (matcher(condition_iter, message, len) == 1)
        {
            return 1;
        }
        condition_iter = rule->conditions[i];
    }
    return 0;
}