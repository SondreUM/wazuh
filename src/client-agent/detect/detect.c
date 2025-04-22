#include "detect.h"
#include "agentd.h"
#include "rule.h"
#include "shared.h"
#include <cjson/cJSON.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#ifdef WAZUH_UNIT_TESTING
void testable_detectmon_thread()
{
    w_detectmon_thread(NULL);
}
#endif

/* datastructure for storing log events in the buffer */
struct log_entry
{
    size_t size;    // size of the log entry
    char log_entry; // log entry start
} __attribute__((packed));
typedef struct log_entry log_entry_t;

/* agent detection state */
agent_detect_state_t detect_state = {.state = STATUS_NORMAL, .hre = NULL, .last_detection = 0};
// rotating log event buffer
log_buffer_t log_buffer[MAX_LOG_DURATION];
static int log_buffer_idx = 0;
static int log_detect_idx = 0;

// rules array
static detect_rule_t* rules[DETECT_RULE_MAX] = {NULL}; // Array of rules

// mutex for the detection state
static pthread_mutex_t state_mutex;
// mutex for the log buffer
static pthread_mutex_t log_mutex;

void detect_init(const char* rule_dir)
{
    // default rule directory
    if (rule_dir == NULL)
    {
        rule_dir = FILTER_RULE_DIRECTORY;
    }

    // Initialize rules array
    for (int i = 0; i < DETECT_RULE_MAX; i++)
    {
        rules[i] = NULL;
    }
    // Parse rules from the directory
    int num_rules = parse_rules(rule_dir, rules);
    if (num_rules < 0)
    {
        merror("Failed to parse rules from directory: %s", rule_dir);
        return;
    }
    mdebug1("Parsed %d rules from directory: %s", num_rules, rule_dir);

    // Initialize mutexes
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
 * Type: helper function
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
 * Type: helper function
 *
 * @return int Index of the oldest HRE, or -1 if not found.
 */
static inline int oldest_hre()
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
    time_t window_start = hre->timestamp - hre->rule->before;
    time_t window_end = hre->timestamp + hre->rule->after;
    // event window duration in seconds
    // time_t window_size = hre->rule->before + hre->rule->after;

    // find the starting timestamp of the event window
    log_buffer_t* log_start = NULL;
    int idx = log_find_timestamp(window_start);
    if (0 <= idx && idx < MAX_LOG_DURATION)
    {
        log_start = &log_buffer[idx];
    }
    else
    {
        mdebug1("Failed to find the event window for the HRE.\n, Unrecoverable error, discarding.");
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    // calculate the size of the context
    // context length in bytes
    log_buffer_t* log_iter = log_start;
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
    snprintf(
        hre->context, context_length, HRE_MESSAGE, hre->rule->name, hre->timestamp, hre->event_trigger, hre->context);
    buffer_append(hre->context);
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

detect_rule_t* scan_log(const char* entry, size_t len)
{
    if (entry == NULL || len <= 0)
    {
        merror("Invalid arguments to scan_log");
        return NULL;
    }
    // iterate over the rules and check if any of them match the entry
    for (int i = 0; rules[i] != NULL; i++)
    {
        if (apply_rule(rules[i], entry, len) == 1)
        {
            // rule matched, return the rule
            return rules[i];
        }
    }
    // no rule matched, return NULL
    return NULL;
}

int detect_buffer_push(const char* entry, size_t size)
{
    if (entry == NULL || size == 0)
    {
        merror("Invalid arguments to detect_buffer_push: size: %ld", size);
        return -1;
    }
    pthread_mutex_lock(&log_mutex);
    time_t now = time(NULL);
    log_buffer_t* current = &log_buffer[log_buffer_idx];

    // check for correct ending
    if (entry[size - 1] != '\n')
        size++;

    // check if the current idx timestamp matches
    if (current->timestamp == now)
    {
        // check if the buffer will overflow, reallocate if needed
        if (current->cursor + size > current->size)
        {
            current->buffer = realloc(current->buffer, current->size + size + sizeof(size_t));
        }
    }
    // timestamp do not exist, create a new log buffer
    else
    {
        // increment the log buffer index
        log_buffer_idx = (log_buffer_idx + 1) % MAX_LOG_DURATION;
        current = &log_buffer[log_buffer_idx];

        // if the existing buffer is larger than default size, free it
        if (current->buffer != NULL && current->size > INITIAL_LOG_BUFFER_SIZE)
        {
            free(current->buffer);
            current->buffer = NULL;
        }

        // check if buffer exists, allocate if needed
        if (current->buffer == NULL)
        {
            current->buffer = malloc(MAX(INITIAL_LOG_BUFFER_SIZE, size));
            if (current->buffer == NULL)
            {
                merror("Failed to allocate memory for the log buffer.");
                pthread_mutex_unlock(&log_mutex);
                return -1;
            }
            current->size = MAX(INITIAL_LOG_BUFFER_SIZE, size);
        }
        // reset metadata
        current->timestamp = now;
        current->cursor = 0;
        current->buffer[0] = '\0';
    }

    // ensure that buffer really exists before writing to it
    if (current->buffer == NULL)
    {
        merror("Tried to write to a NULL buffer.");
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    // insert the size of the entry at the beginning
    // uses the log_entry_t struct to store the size of the entry
    memcpy(current->buffer + current->cursor, &size, sizeof(size_t));
    // append the entry to the buffer
    memcpy(current->buffer + current->cursor + sizeof(size_t), entry, size);
    // update the cursor
    current->size += size;
    // set line ending
    current->buffer[current->cursor + size] = '\0';

    pthread_mutex_unlock(&log_mutex);
    return 0;
}

detect_state_t detect_update(hre_t* new_hre)
{
    pthread_mutex_lock(&state_mutex);

    // if a new HRE is provided, add it to the list
    if (new_hre != NULL)
    {
        // if the HRE array is full, delete the oldest HRE
        if (num_hre() <= MAX_HRE)
        {
            int oldest = oldest_hre();
            if (oldest != -1)
            {
                delete_hre(detect_state.hre[oldest]);
                detect_state.hre[oldest] = new_hre;
            }
        }
        else
        {

            for (int i = 0; i < MAX_HRE; i++)
            {
                if (detect_state.hre[i] == NULL)
                {
                    detect_state.hre[i] = new_hre;
                    break;
                }
            }
        }
    }

    pthread_mutex_unlock(&state_mutex);
    return detect_state.state;
}

/**
 * @brief scans the log buffer for events and applies rules to them.
 * if a rule matches, it will create a new HRE and add it to the list.
 *
 * @param log_buffer the log buffer to scan.
 * @return int the number of detections found in the log buffer.
 */
inline static int scan_log_buffer(log_buffer_t* log_buffer)
{
    if (log_buffer == NULL)
    {
        merror("Trying to scan a NULL log buffer.");
        return -1;
    }
    else if (log_buffer->cursor == 0 || log_buffer->buffer == NULL || log_buffer->timestamp == 0)
    {
        mdebug2("Trying to scan an empty log buffer.");
        return -1;
    }

    int detections = 0;
    size_t read_cursor = 0;

    // read each log entry in the buffer
    for (; read_cursor <= log_buffer->cursor;)
    {
        // find the end of the log entry
        log_entry_t* entry = (log_entry_t*)(log_buffer->buffer + read_cursor);

        // apply rules to the log entry
        detect_rule_t* rule = scan_log(&entry->log_entry, entry->size);
        if (rule != NULL)
        {
            // create a new HRE
            hre_t* new_hre = malloc(sizeof(hre_t));
            if (new_hre == NULL)
            {
                merror("Failed to allocate memory for the HRE.");
                return -1;
            }
            new_hre->rule = rule;
            new_hre->timestamp = log_buffer->timestamp;
            new_hre->event_trigger = strndup(log_buffer->buffer + read_cursor, entry->size);
            if (new_hre->event_trigger == NULL)
            {
                merror("Failed to allocate memory for the event trigger.");
                free(new_hre);
                return -1;
            }
            detect_update(new_hre);
            detections++;
        }
        // move the read cursor to the next log entry
        read_cursor += entry->size + sizeof(log_entry_t);
        // check if the read cursor is out of bounds
        if (read_cursor >= log_buffer->cursor)
        {
            break;
        }
    }
    return detections;
}

void* w_detectmon_thread(__attribute__((unused)) void* arg)
{
    mdebug1("Detect thread started");
    while (1)
    {
        mdebug1("Detect thread running, time: %ld", time(NULL));
        // scan the log buffer for new events
        for (; log_detect_idx < log_buffer_idx; log_detect_idx++)
        {
            int detections = scan_log_buffer(&log_buffer[log_detect_idx]);
            mdebug1("Detected %d events in log buffer %d", detections, log_detect_idx);
        }

        // update the agent state
        hre_update();
        if (num_hre() == 0)
            detect_state.state = STATUS_NORMAL;
        sleep(1);
    }
}