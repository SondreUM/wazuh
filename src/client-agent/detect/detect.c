#include "detect.h"
#include "agentd.h"
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

void testable_detectmon_thread()
{
    w_detectmon_thread(NULL);
}
#else
#define STATIC static
#endif

/* Util functions */
static inline int log_find_timestamp(time_t timestamp);
static inline int oldest_hre();
static inline int num_hre();

/* agent detection state */
agent_detect_state_t detect_state = {.state = STATUS_NORMAL, .hre = NULL, .last_detection = 0};

/* Context log buffer */
// rotating log event buffer
log_buffer_t log_buffer[MAX_LOG_DURATION];
// index of the active log buffer
static int log_buffer_idx = 0;
// index of the detecion agent
static int log_detect_idx = 0;
// mutex for the log buffer
static pthread_mutex_t log_mutex;

/* Detection rules */
// mutex for the detection state
static pthread_mutex_t state_mutex;
// rules array
static detect_rule_t* rules[DETECT_RULE_MAX] = {NULL}; // Array of rules

void detect_init(const char* rule_dir)
{
    // default rule directory
    if (rule_dir == NULL)
    {
        rule_dir = DETECT_RULE_DIRECTORY;
    }

    // Initialize rules array
    for (int i = 0; i < DETECT_RULE_MAX; i++)
    {
        rules[i] = NULL;
    }
    // Parse rules from the directory
    int num_rules = parse_rules(rule_dir, rules, DETECT_RULE_MAX);
    if (num_rules < 0)
    {
        merror("Failed to parse rules from directory: %s", rule_dir);
        return;
    }
    minfo("Loaded %d rule(s) from '%s'", num_rules, rule_dir);

    // initialize mutexes
    pthread_mutex_init(&state_mutex, NULL);
    pthread_mutex_init(&log_mutex, NULL);

    // initialize the log buffer with empty values
    for (int i = 0; i < MAX_LOG_DURATION; i++)
    {
        log_buffer[i].timestamp = 0;
        log_buffer[i].size = 0;
        log_buffer[i].cursor = 0;
        log_buffer[i].buffer = NULL;
    }

    // initialize the HRE array
    for (int i = 0; i < MAX_HRE; i++)
    {
        detect_state.hre[i] = NULL;
    }
    detect_state.state = STATUS_NORMAL;
    detect_state.last_detection = 0;

    // rules = parse_rule();
}

detect_state_t detect_get_state()
{
    detect_state_t state;
    pthread_mutex_lock(&state_mutex);
    state = detect_state.state;
    pthread_mutex_unlock(&state_mutex);
    return state;
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
    pthread_mutex_lock(&log_mutex);
    time_t window_start = hre->timestamp - hre->rule->before;
    // time_t window_end = hre->timestamp + hre->rule->after;
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

    /* construct the context object */
    cJSON* context = NULL;
    log_buffer_t* log_iter = log_start;
    for (int i = 0; i < hre->rule->before + hre->rule->after; i++)
    {
        if (log_iter->timestamp != hre->timestamp + i)
        {
            mdebug1(
                "Out of order log buffer, expected timestamp %ld, got %ld.\n", hre->timestamp + i, log_iter->timestamp);
            log_iter = &log_buffer[(i + idx) % MAX_LOG_DURATION];
            pthread_mutex_unlock(&log_mutex);
            continue;
        }
        // copy the log to the context
        format_buffer2json(context, log_iter);

        log_iter = &log_buffer[(i + idx) % MAX_LOG_DURATION];
    }
    // buffer operation is done, unlock the mutex
    pthread_mutex_unlock(&log_mutex);

    // format the message for sending
    char* hre_json = format_hre_2json(hre, context);

    // queue the event for sending
    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
    if (send_msg(hre_json, -1) < 0)
    {
        merror("Failed to send the HRE message.");
        free(hre_json);
        return;
    }
    mdebug1("Dispatched HRE: %s", hre_json);

    // free the event message
    free(hre_json);
}

/**
 * @brief checks the state of HREs and dispatches completed events.
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
            pthread_mutex_lock(&state_mutex);
            // dispatch the HRE
            dispatch_hre(detect_state.hre[i]);
            // delete the HRE
            delete_hre(detect_state.hre[i]);
            if (num_hre() == 0)
            {
                detect_state.state = STATUS_NORMAL;
            }
            pthread_mutex_unlock(&state_mutex);
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
    if (entry == NULL || size <= 0)
    {
        merror("Invalid arguments to detect_buffer_push: size: %ld", size);
        return -1;
    }
    pthread_mutex_lock(&log_mutex);
    time_t now = time(NULL);
    log_buffer_t* current = &log_buffer[log_buffer_idx];

    // check if the current idx timestamp matches
    if (current->timestamp == now)
    {
        // check if the buffer will overflow, reallocate if needed
        if (current->cursor + size > current->size)
        {
            current->buffer = realloc(current->buffer, current->size + size + 1);
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
        current->buffer[current->size - 1] = '\0';
    }

    // ensure that buffer really exists before writing to it
    if (current->buffer == NULL)
    {
        merror("Tried to write to a NULL buffer.");
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    // append the entry to the buffer
    memcpy(current->buffer + current->cursor, entry, size);
    // ensure that the entry is null terminated
    if (entry[size] != '\0')
    {
        current->buffer[current->cursor + size] = '\0';
        size++;
    }
    // update the cursor
    current->cursor += size + sizeof(size_t);

    pthread_mutex_unlock(&log_mutex);
    return 0;
}

detect_state_t insert_hre(hre_t* new_hre)
{
    pthread_mutex_lock(&state_mutex);

    // if a new HRE is provided, add it to the list
    if (new_hre != NULL)
    {
        mdebug1("Inserting new HRE: %s", new_hre->event_trigger);
        mdebug1("%s", format_hre_2json(new_hre, NULL));
        // if the HRE array is full, dispatch the oldest HRE
        if (num_hre() <= MAX_HRE)
        {
            int oldest = oldest_hre();
            // fallback to random if for some reason the oldest is not found
            if (oldest == -1)
            {
                mwarn("Failed to find the oldest HRE.");
                oldest = rand() % MAX_HRE;
            }
            dispatch_hre(detect_state.hre[oldest]);
            detect_state.hre[oldest] = new_hre;
        }
        else
        {
            // insert the new HRE into the array
            for (int i = 0; i < MAX_HRE; i++)
            {
                if (detect_state.hre[i] == NULL)
                {
                    detect_state.hre[i] = new_hre;
                    break;
                }
            }
        }
        detect_state.state = STATUS_HRE;
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
        mdebug1("Trying to scan an empty log buffer.");
        return -1;
    }

    int detections = 0;
    size_t read_cursor = 0;

    // read each log entry in the buffer
    for (size_t entry_len = 0; read_cursor <= log_buffer->cursor;)
    {
        // search for the next zero byte
        entry_len = strnlen(&log_buffer->buffer[read_cursor], log_buffer->cursor - read_cursor);

        // apply rules to the log entry
        detect_rule_t* rule = scan_log(&log_buffer->buffer[read_cursor], entry_len);
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
            new_hre->event_trigger = strndup(&log_buffer->buffer[read_cursor], entry_len);
            if (new_hre->event_trigger == NULL)
            {
                merror("Failed to allocate memory for the event trigger.");
                free(new_hre);
                return -1;
            }
            insert_hre(new_hre);
            detections++;
        }
        // move the read cursor to the next log entry
        read_cursor += entry_len + 1;
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
    mdebug1("Detect thread starting...");
    while (1)
    {
        // scan the log buffer for new events
        for (int detections = 0; log_detect_idx < log_buffer_idx;
             log_detect_idx = (log_detect_idx + 1) % MAX_LOG_DURATION)
        {
            // check if the log buffer is empty
            if (log_buffer[log_detect_idx].cursor == 0 || log_buffer[log_detect_idx].buffer == NULL)
            {
                mdebug1("Log buffer %d is empty, skipping.", log_detect_idx);
                continue;
            }
            // scan the log buffer for events
            mdebug1("Scanning log buffer %ld, contains %ld bytes",
                    log_buffer[log_detect_idx].timestamp,
                    log_buffer[log_detect_idx].cursor);
            detections = scan_log_buffer(&log_buffer[log_detect_idx]);
            mdebug1("BUFFER: %s", log_buffer[log_detect_idx].buffer);
            mdebug1(
                "Scanned buffer for timestamp %ld, found %d HRE(s)", log_buffer[log_detect_idx].timestamp, detections);
        }

        // update the agent state
        hre_update();
        if (num_hre() == 0)
            detect_state.state = STATUS_NORMAL;
        sleep(1);
    }
}

/* Util */

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