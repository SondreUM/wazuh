#ifndef FILTER_H
#define FILTER_H

#include "detect/rule.h"
#include "shared.h"

#define FILTER_RULE_DIRECTORY "/var/ossec/etc/filter/"
#define FILTER_RULE_MAX       100

detect_rule_t** filter_init(const char* rule_dir);

void filter_free(detect_rule_t** rules);

int filter_log_check(detect_rule_t** rules, const char* message, size_t length);

#endif /* FILTER_H */