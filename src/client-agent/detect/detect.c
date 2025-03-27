#include "detect.h"
#include <assert.h>
#include <cstddef>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/* agent detection state */
agent_detect_state_t detect_state = {.state = STATUS_NORMAL, .hre = NULL, .last_detection = 0};
// rotating log event buffer
log_buffer_t log_buffer[MAX_LOG_DURATION];
// HRE array
hre_t* hre_array[MAX_HRE];

// mutex for the detection state
static pthread_mutex_t state_mutex;
// mutex for the log buffer
static pthread_mutex_t log_mutex;
// mutex for the HRE array
static pthread_mutex_t hre_mutex;

void detect_init()
{
    pthread_mutex_init(&state_mutex, NULL);
    pthread_mutex_init(&log_mutex, NULL);
    pthread_mutex_init(&hre_mutex, NULL);
}

static inline int log_find_timestamp(time_t timestamp)
{
    for (int i = 0; i < MAX_LOG_DURATION; i++)
    {
        if (log_buffer[i].timestamp == timestamp)
        {
            return i;
        }
    }
    return -1;
}

void delete_hre(hre_t* hre)
{
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (&hre_array[i] == hre)
        {
            hre_array[i] = NULL;
            break;
        }
    }
    if (hre == NULL)
    {
        return;
    }

    free(hre->event_trigger);
    free(hre->context);
    free(hre);
}

void dispatch_hre(hre_t* hre)
{

    // copy the context from buffer
    pthread_mutex_lock(&log_mutex);
    char* cursor = NULL;
    time_t window_start = hre->timestamp - hre->rule->before;
    time_t window_end = hre->timestamp + hre->rule->after;
    // event window duration in seconds
    time_t window_size = hre->rule->before + hre->rule->after;

    // find the starting timestamp of the event window
    log_buffer_t* current = NULL;
    int idx = log_find_timestamp(window_start);
    if (0 <= idx && idx < MAX_LOG_DURATION)
    {
        current = &log_buffer[idx];
    }
    else
    {
        mdebug1("Failed to find the event window for the HRE.\n, Unrecoverable error, discarding.");
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    assert(current != NULL);

    // calculate the size of the context
    // context length in bytes
    log_buffer_t* log_iter;
    size_t context_length = 0;

    for (int i = idx; log_iter->timestamp <= window_end; i++)
    {
        log_iter = &log_buffer[(i) % MAX_LOG_DURATION];

        // debug: detect out of order log buffer
        if (log_iter->timestamp < hre->timestamp - hre->rule->before)
        {
            mdebug1("Out of order log buffer, expected timestamp %ld, got %ld.\n",
                    hre->timestamp - hre->rule->before,
                    log_iter->timestamp);
        }
        else if (log_iter->timestamp > window_end)
        {
            mdebug1("Out of order log buffer, expected timestamp %ld, got %ld.\n", window_end, log_iter->timestamp);
        }

        // sum the size of the log buffer
        context_length += log_iter->size;
    }

    // TODO: limit the context length to a maximum size
    // copy the context to the HRE
    hre->context = malloc(context_length + 1);
    if (hre->context == NULL)
    {
        pthread_mutex_unlock(&log_mutex);
        merror("Failed to allocate memory for the HRE context.");
        return;
    }
    char* context_cursor = hre->context;
    for (int i = 0; i < hre->rule->before + hre->rule->after; i++)
    {
        if (log_iter->timestamp != hre->timestamp + i)
        {
            mdebug1(
                "Out of order log buffer, expected timestamp %ld, got %ld.\n", hre->timestamp + i, log_iter->timestamp);
            log_iter = log_iter->next;
            continue;
        }
        size_t to_copy = log_iter->size;
        // limit the copy to the remaining space in the context
        // TODO: handle the case where the context is larger than the remaining space
        if (to_copy > context_length)
        {
            to_copy = context_length;
        }

        memcpy(context_cursor, log_iter->buffer, to_copy);
        context_cursor += to_copy;
        context_length -= to_copy;
        log_iter = log_iter->next;
    }
    pthread_mutex_unlock(&log_mutex);

    // format the event and send it to the server
    char* event = NULL;
    size_t message_length =
        snprintf(NULL, 0, HRE_MESSAGE, hre->rule->name, hre->timestamp, hre->event_trigger, hre->context);
}

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
            // finalize the event and send it to the server
            dispatch_hre(current);
            // remove the HRE from the list
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
