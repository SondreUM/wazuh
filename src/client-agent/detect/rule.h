#ifndef RULE_H
#define RULE_H

#include "shared.h"
#include <cjson/cJSON.h>
#include <stdint.h>
#include <time.h>

// Default values for before and after event windows
#define RULE_DEFAULT_BEFORE 1
#define RULE_DEFAULT_AFTER  3
// Maximum number of conditions and extensions
// Additional values will be ignored
#define RULE_MAX_CONDITIONS 10
#define RULE_MAX_EXTENSIONS 10
// Maximum rule->name before truncation
#define RULE_MAX_NAME 64
// Maximum rule->description before truncation
#define RULE_MAX_DESC 256

static const char RULE_INFO[] = "RuleID: %ld, Name: %s, Before: %ld, After: %ld, Description: %s";
static const char RULE_JSON_FORMAT[] =
    R"({ "id": %ld, "before": %ld, "after": %ld, "name": "%s", "description": "%s", "conditions": %s, "extensions": %s})";
static const char RULE_EXT_JSON_FORMAT[] = R"({"field": "%s", "value": "%s"})";
static const char RULE_COND_JSON_FORMAT[] = R"({"matcher": "%s", "string": "%s"})";

typedef enum match_rule
{
    UNDEFINED_MATCHER = -1, ///< Undefined matcher
    STARTSWITH,             ///< Match the start of the message
    ENDSWITH,               ///< Match the end of the message
    CONTAINS,               ///< Match the message
    REGEX,                  ///< Match the message with a regular expression

    num_matchers
} match_rule_t;

/**
 * @brief Rule extensions
 *
 */
typedef struct detect_rule_extension
{
    char* field; ///< Name of the field
    char* value; ///< Value of the field
} detect_rule_extension_t;

/**
 * @brief Rule extensions
 *
 */
typedef struct detect_rule_condition
{
    match_rule_t matcher; ///< Matcher type
    char* pattern;        ///< String to match
} detect_rule_condition_t;

/**
 * @brief Detection rule.
 */
typedef struct detect_rule
{
    int64_t id;                           ///< unique id
    time_t before;                        ///< activation windows ahead of the event
    time_t after;                         ///< activation windows after the event
    char* name;                           ///< rule name
    char* description;                    ///< rule description
    detect_rule_condition_t** conditions; ///< rule conditions
    detect_rule_extension_t** ext;        ///< rule extensions

} detect_rule_t;

/**
 * @brief Parse a rule from JSON
 *
 * @param json_string The JSON string to parse
 * @return detect_rule_t* The parsed rule or NULL on failure
 */
detect_rule_t* parse_rule(const char* json_string);

/**
 * @brief Parse detection rules from a directory
 *
 * @param rule_dir The directory containing the rules
 * @param rules The array of rules to populate
 * @return int The number of rules parsed or -1 on error
 */
int parse_rules(const char* rule_dir, detect_rule_t** rules, size_t max_rules);

/**
 * @brief Free a rule and all its resources
 *
 * @param rule The rule to free
 */
void free_rule(detect_rule_t* rule);

/**
 * @brief Format a string with rule information
 *
 * @param rule The rule to print
 */
char* rule_info(detect_rule_t* rule);

/**
 * @brief formats a detect_rule_t struct into a printable string
 * @param rule pointer to detect_rule_t struct to format
 * @return char* allocated string containing formatted output
 *
 * Caller is responsible for freeing the returned string with free()
 */
char* format_detect_rule(const detect_rule_t* rule);

// provided by matcher.c
/**
 * @brief Apply a rule to a message
 *
 * @param rule The rule to apply
 * @param message The message to apply the rule to
 * @return int 1 if the rule matches, 0 if it doesn't, -1 on error
 */
int apply_rule(detect_rule_t* rule, const char* message, size_t len);

#endif /* RULE_H */