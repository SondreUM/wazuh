#include "detect.h"
#include "shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void prune_log_buffer(log_buffer_t* log_buffer)
{
    if (log_buffer == NULL)
    {
        return;
    }

    time_t now = time(NULL);

    for (int i = 0; i < MAX_LOG_DURATION; i++)
    {
        if (log_buffer->timestamp == 0)
        {
            continue;
        }
        if (log_buffer->timestamp + MAX_LOG_DURATION < now)
        {
            log_buffer->timestamp = 0;
            free(log_buffer->buffer);
            log_buffer->buffer = NULL;
            log_buffer->size = 0;
            log_buffer->cursor = 0;
        }
    }
}