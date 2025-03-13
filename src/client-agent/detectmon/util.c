#include "rule.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Print a rule for debugging
 *
 * @param rule The rule to print
 */
void print_rule(detect_rule_t* rule)
{
    if (!rule)
        return;

    printf("Rule ID: %d\n", rule->id);
    printf("Name: %s\n", rule->name ? rule->name : "N/A");
    printf("Description: %s\n", rule->description ? rule->description : "N/A");
    printf("Before: %d\n", rule->before);
    printf("After: %d\n", rule->after);

    printf("Conditions:\n");
    if (rule->conditions)
    {
        for (int i = 0; rule->conditions[i] != NULL; i++)
        {
            printf(
                "  - Type: %s, Value: %s\n", match_rule_str[rule->conditions[i]->matcher], rule->conditions[i]->string);
        }
    }
    else
    {
        printf("  None\n");
    }

    printf("Extensions:\n");
    if (rule->ext)
    {
        for (int i = 0; rule->ext[i] != NULL; i++)
        {
            printf("  - %s: ", rule->ext[i]->field);

            // We don't know the type of value, so we'll just print the address
            printf("%p\n", rule->ext[i]->value);
        }
    }
    else
    {
        printf("  None\n");
    }
}