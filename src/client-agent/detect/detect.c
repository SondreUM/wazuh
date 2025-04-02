#include "detect.h"
#include "rule.h"
#include "shared.h"
#include <assert.h>
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
int log_buffer_idx = 0;
// rules
detect_rule_t** rules;

// mutex for the detection state
static pthread_mutex_t state_mutex;
// mutex for the log buffer
static pthread_mutex_t log_mutex;

void detect_init()
{
    pthread_mutex_init(&state_mutex, NULL);
    pthread_mutex_init(&log_mutex, NULL);

    for (int i = 0; i < MAX_LOG_DURATION; i++)
    {
        log_buffer[i].timestamp = 0;
        log_buffer[i].size = 0;
        log_buffer[i].cursor = 0;
        log_buffer[i].buffer = NULL;
    }

    for (int i = 0; i < MAX_HRE; i++)
    {
        detect_state.hre[i] = NULL;
    }
    detect_state.state = STATUS_NORMAL;
    detect_state.last_detection = 0;

    // rules = parse_rule();
}

/**
 * @brief Finds the index of the log buffer with the given timestamp.
 *
 * @param timestamp Timestamp to search for.
 * @return int Index of the log buffer with the given timestamp, or -1 if not found.
 */
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

/**
 * @brief Counts the number of HREs in the array.
 *
 * @return int Number of HREs in the array.
 */
static inline int num_hre()
{
    int count = 0;
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (detect_state.hre[i] != NULL)
        {
            count++;
        }
    }
    return count;
}

/**
 * @brief Finds the index of the oldest HRE in the array.
 *
 * @return int Index of the oldest HRE, or -1 if not found.
 */
static int oldest_hre()
{
    int oldest = -1;
    time_t oldest_time = 0;
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (detect_state.hre[i] == NULL)
        {
            continue;
        }
        if (oldest == -1 || detect_state.hre[i]->timestamp < oldest_time)
        {
            oldest = i;
            oldest_time = detect_state.hre[i]->timestamp;
        }
    }
    return oldest;
}

void delete_hre(hre_t* hre)
{
    if (hre == NULL)
    {
        return;
    }
    // remove the HRE from the array if exists
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (detect_state.hre[i] == hre)
        {
            detect_state.hre[i] = NULL;
            break;
        }
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
            log_iter = &log_buffer[(i + idx) % MAX_LOG_DURATION];
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
        log_iter = &log_buffer[(i + idx) % MAX_LOG_DURATION];
    }
    pthread_mutex_unlock(&log_mutex);

    // format the event and send it to the server
    char* event = NULL;
    size_t message_length =
        snprintf(NULL, 0, HRE_MESSAGE, hre->rule->name, hre->timestamp, hre->event_trigger, hre->context);
}

detect_state_t detect_get_state()
{
    detect_state_t state;
    pthread_mutex_lock(&state_mutex);
    state = detect_state.state;
    pthread_mutex_unlock(&state_mutex);
    return state;
}

/**
 * @brief checks HREs and dispatches completed events.
 * requires the state_mutex to be aquired before calling.
 */
static void hre_update()
{
    for (int i = 0; i < MAX_HRE; i++)
    {
        if (detect_state.hre[i] == NULL)
        {
            continue;
        }
        // check if the HRE is within the event window
        if (detect_state.hre[i]->timestamp + detect_state.hre[i]->rule->after < time(NULL))
        {
            // dispatch the HRE
            dispatch_hre(detect_state.hre[i]);
            // delete the HRE
            delete_hre(detect_state.hre[i]);
            detect_state.hre[i] = NULL;
        }
    }
}

detect_rule_t* scan_log(const char* entry)
{
    if (entry == NULL || rules == NULL)
    {
        return NULL;
    }
    // iterate over the rules and check if any of them match the entry
    for (int i = 0; rules[i] != NULL; i++)
    {
        if (apply_rule(rules[i], entry) == 1)
        {
            // rule matched, return the rule
            return rules[i];
        }
    }
    // no rule matched, return NULL
    return NULL;
}

void append_log_buffer(const char* entry, size_t size)
{
    if (entry == NULL || size == 0)
    {
        return;
    }
    time_t now = time(NULL);
    pthread_mutex_lock(&log_mutex);
    log_buffer_t* current = &log_buffer[log_buffer_idx];
    // check if the timestamp matches
    if (current->timestamp == now)
    {
        // check if the buffer will overflow, reallocate if needed
        if (current->cursor + size > current->size)
        {
            current->buffer = realloc(current->buffer, current->size + size);
        }
    }
    else
    {
        // timestamp not found, create a new log buffer
        current->timestamp = now;
        current->size = INITIAL_LOG_BUFFER_SIZE;
        current->cursor = 0;
        current->buffer = malloc(size);
    }

    // check that buffer really exists
    if (current->buffer == NULL)
    {
        merror("Failed to allocate memory for the log buffer.");
        return;
    }
    // append the entry to the buffer
    memcpy(current->buffer + current->cursor, entry, size);
    current->size += size;

    pthread_mutex_unlock(&log_mutex);
}

detect_state_t detect_update(hre_t* new_hre)
{
    pthread_mutex_lock(&state_mutex);

    // if a new HRE is provided, add it to the list
    if (new_hre != NULL)
    {
        for (int i = 0; i < MAX_HRE; i++)
        {
            if (detect_state.hre[i] == NULL)
            {
                detect_state.hre[i] = new_hre;
                break;
            }
        }
        // if the HRE array is full, delete the oldest HRE
    }

    // check the current HREs
    hre_update();

    // update the agent state
    if (num_hre() == 0)
        detect_state.state = STATUS_NORMAL;

    pthread_mutex_unlock(&state_mutex);
    return detect_state.state;
}

void* w_detectmon_thread(__attribute__((unused)) void* arg)
{
    time_t now;
    while (1)
    {
        now = time(NULL);

        detect_update(NULL);

        sleep(3);
    }
}