#ifndef FILTER_H
#define FILTER_H

#include "detect/rule.h"
#include "shared.h"

#define FILTER_RULE_DIRECTORY "/var/ossec/etc/filter/"
#define FILTER_RULE_MAX       100

/**
 * @brief Initialize the filter module.
 *
 * @param rule_dir The directory containing the filter rules or NULL for default.
 */
void filter_init(const char* rule_dir);

/**
 * @brief Check if a log message matches any filter rules.
 *
 * @param rules The array of filter rules.
 * @param message The log message to check.
 * @param length The length of the log message.
 * @return int The ID of the matching rule, or 0 if no match is found.
 */
int filter_log_check(const char* message, size_t length);

/**
 * @brief Free the filter rules.
 *
 * @param rules The array of filter rules to free.
 */
void filter_free(detect_rule_t** rules);

#endif /* FILTER_H */