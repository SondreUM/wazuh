#include "detect.h"
#include "util.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* agent detection state */
agent_detect_state_t detect_state = {.state = STATUS_NORMAL, .hre = NULL, .last_detection = 0};
// mutex for the detection state
static pthread_mutex_t state_mutex;
// rotating log event buffer
static log_buffer_t log_buffer = NULL;
// mutex for the log buffer
static pthread_mutex_t log_mutex;

void detect_init()
{
    pthread_mutex_init(&state_mutex, NULL);
    pthread_mutex_init(&log_mutex, NULL);
}

void dispatch_hre(hre_t* hre) {}

/**
 * @brief checks HREs and dispatches completed events.
 * requires the state_mutex to be aquired before calling.
 */
static void hre_update()
{
    hre_t* current = detect_state.hre;
    hre_t* prev = NULL;
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (current == NULL)
        {
            break;
        }

        // check if the event window has ended
        if (current->rule->after + current->timestamp < time(NULL))
        {
            dispatch_hre(current);
            if (prev == NULL)
            {
                detect_state.hre = current->next;
            }
            else
            {
                prev->next = current->next;
            }
        }
        prev = current;
        current = current->next;
    }
}

detect_state_t detect_update(hre_t* new_hre)
{
    pthread_mutex_lock(&state_mutex);

    // if a new HRE is provided, add it to the list
    if (new_hre != NULL)
    {
        hre_t* first = detect_state.hre;
        detect_state.hre = new_hre;
        if (first != NULL)
        {
            new_hre->next = first;
        }
    }

    // check the current HREs
    hre_update();

    // update the agent state
    if (detect_state.hre == NULL)
        detect_state.state = STATUS_NORMAL;

    pthread_mutex_unlock(&state_mutex);
    return detect_state.state;
}

detect_state_t detect_get_state()
{
    detect_state_t state;
    pthread_mutex_lock(&state_mutex);
    state = detect_state.state;
    pthread_mutex_unlock(&state_mutex);
    return state;
}
