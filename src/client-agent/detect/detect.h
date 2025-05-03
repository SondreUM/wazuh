#ifndef DETECT_H
#define DETECT_H

#include "rule.h"
#include "shared.h"
#include "state.h"
#include "wazuhdb_op.h"
#include <time.h>

/* detection definitions  */
// Maximum number of HREs to process concurrently
#define MAX_HRE 10
// Maximum duration of the log buffer in seconds
#define MAX_LOG_DURATION 60
// Maximum number of rules to that can be loaded
#define DETECT_RULE_MAX 100
// Directory containing the detection rules
// Each rule should be in a separate file, using the .json extension
#define DETECT_RULE_DIRECTORY "/var/ossec/etc/detect/"
#define MAX_CONTEXT_SIZE      OS_MAXSTR
// size of the initial log buffer for each timestamp
#define INITIAL_LOG_BUFFER_SIZE OS_BUFFER_SIZE

static const char HRE_MESSAGE[] = "HRE detected: rule %s, trigger %s at %ld";
static const char HRE_JSON_FORMAT[] = R"({"timestamp": %ld, "event_trigger": "%s", "rule": %s, "context": "%s"})";

/**
 * @brief Current detection state of the agent.
 */
typedef enum detect_state
{
    STATUS_NORMAL = 0,
    STATUS_HRE,
} detect_state_t;

/**
 * @brief High Risk Event.
 */
typedef struct hre
{
    time_t timestamp;    // Timestamp of the event
    char* event_trigger; // Event that triggered the rule
    char* context;       // Context of the event, NULL until window is closed
    detect_rule_t* rule; // Rule that triggered the event
} hre_t;

/**
 * @brief Detection state of the agent.
 */
typedef struct agent_detect_state
{
    detect_state_t state;  // Current detection state
    time_t last_detection; // Timestamp of the last detection
    hre_t* hre[MAX_HRE];   // High Risk Events, NULL if none
} agent_detect_state_t;

typedef struct log_buffer
{
    time_t timestamp; // Timestamp of the log,
    size_t size;      // Size of the buffer
    size_t cursor;    // Current position in the buffer
    char* buffer;     // Pointer to the buffer
} log_buffer_t;

/**
 * @brief initializes the detection module.
 *
 * @param rule_dir directory containing the detection rules
 * @note if rule_dir is NULL, the default directory will be used.
 */
void detect_init(const char* rule_dir);

/**
 * @brief finalize the HRE event and send it to the server.
 * Formats the event into Standard OSSEC event format,
 * ref: https://documentation.wazuh.com/current/development/message-format.html
 * Will free the HRE when completed.
 *
 * @param hre completed HRE, the structure will be freed by the function
 */
void dispatch_hre(hre_t* hre);

/**
 * @brief get the current detection state of the agent.
 *
 * @return detect_state_t integer of type detect_state_t representing the current state of the agent.
 */
detect_state_t detect_get_state();

/**
 * @brief insert a new HRE, acti
 *
 * @param new new HRE to add to the list, NULL if no new HRE
 * @return detect_state_t the new state of the agent
 */
detect_state_t insert_hre(hre_t* new_hre);

/**
 * @brief applies the detection rules to the log entry.
 *
 * @param entry log entry to scan
 * @return detect_rule_t* the rule that matched the entry, NULL if no rule matched
 */
detect_rule_t* scan_log(const char* entry, size_t len);

/**
 * @brief scans the log buffer for events and applies rules to them.
 * if a rule matches, it will create a new HRE and add it to the list.
 *
 * @param log_buffer the log buffer to scan.
 * @return int the number of detections found in the log buffer.
 */
void prune_log_buffer(log_buffer_t* log_buffer);

/**
 * @brief Pushes a log entry to the detection buffer.
 * This function will append the entry to the buffer and update the size.
 *
 * @param entry The log entry to push.
 * @param size The size of the log entry.
 * @return int 0 on success, -1 on failure.
 */
int detect_buffer_push(const char* entry, size_t size);

/**
 * @brief Formats a log buffer into a JSON array
 *
 * @param array NULL or a cJSON array to append to
 * @param buffer log_buffer_t* buffer to format
 * @return cJSON* JSON array containing the formatted log entries
 */
cJSON* format_buffer2json(cJSON* array, log_buffer_t* buffer);

/**
 * @brief Formats a detect_rule_t struct into a printable string
 * Uses cJSON to format the HRE into a JSON string.
 *
 * @param rule pointer to detect_rule_t struct to format
 * @param context_array cJSON array containing the context
 * @return char* allocated string containing formatted output
 *
 * Caller is responsible for freeing the returned string with free()
 */
char* format_hre_2json(hre_t* hre, cJSON* context_array);

/**
 * @brief Thread to update the detection state.
 * This thread will run in a loop and update the detection state every second.
 *
 * @param arg Unused argument.
 * @return void* NULL
 */
#ifdef WIN32
DWORD WINAPI w_detectmon_thread(__attribute__((unused)) LPVOID arg);
#else
void* w_detectmon_thread(__attribute__((unused)) void* arg);
#endif

#endif /* DETECT_H */