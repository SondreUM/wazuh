#ifndef DETECT_H
#define DETECT_H

#include "rule.h"
#include <time.h>

#define MAX_HRE 10

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
    struct hre* next;    // Next HRE, NULL if last
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
    time_t timestamp;
    size_t size;
    size_t cursor;
    struct log_buffer* next;
    char* buffer;
} log_buffer_t;

/**
 * @brief Initialize the detection module.
 */
void detect_init();

/**
 * @brief adds the log context to a HRE and sends it to the dispatcher.
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