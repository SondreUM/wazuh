#ifndef DETECT_H
#define DETECT_H

#include "agentd.h"
#include "read-agents.h"
#include "rule.h"
#include "shared.h"
#include <time.h>

// Maximum number of HREs to process concurrently
#define MAX_HRE 10
// Maximum duration of the log buffer in seconds
#define MAX_LOG_DURATION 60

#ifndef merror
#define merror(msg) fprintf(stderr, "Error: %s\n", msg)
#endif /* merror */
#ifndef mwarning
#define mwarning(msg) fprintf(stderr, "Warning: %s\n", msg)
#endif /* mwarning */
#ifndef mdebug1
#define mdebug1(...) fprintf(stdout, __VA_ARGS__)
#endif /* mdebug1 */
#ifndef merror
#define merror(...) fprintf(stderr, __VA_ARGS__)
#endif /* merror */

const char HRE_MESSAGE[] = "High Risk Event detected: %s, timestamp %d, trigger %s, context: %s";

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
    hre_t* hre;            // High Risk Events, NULL if none
} agent_detect_state_t;

typedef struct log_buffer
{
    time_t timestamp; // Timestamp of the log,
    size_t size;
    size_t cursor;
    char* buffer;
} log_buffer_t;

/**
 * @brief Initialize the detection module.
 */
void detect_init();

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
 * @brief updates the internal detection state of the agent
 *
 * @param new new HRE to add to the list, NULL if no new HRE
 * @return detect_state_t the new state of the agent
 */
detect_state_t detect_update(hre_t* new_hre);

/**
 * @brief get the current detection state of the agent.
 *
 * @return detect_state_t integer of type detect_state_t representing the current state of the agent.
 */
detect_state_t detect_get_state();

#endif /* DETECT_H */