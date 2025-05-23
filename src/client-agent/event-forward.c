/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "agentd.h"
#include "os_net/os_net.h"
#include "sec.h"
#include "shared.h"
#include <string.h>
#include <sys/types.h>

#ifdef DYNAMIC_DETECT
#include "detect/detect.h"
#include "filter.h"
#endif

static u_int64_t b_sent = 0;     /* Number of B sent */
static u_int64_t b_filtered = 0; /* Number of B filtered */

/* Receive a message locally on the agent and forward it to the manager */
void* EventForward()
{
    ssize_t recv_b;
    char msg[OS_MAXSTR + 1];

    /* Initialize variables */
    msg[0] = '\0';
    msg[OS_MAXSTR] = '\0';

    while ((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
    {
        msg[recv_b] = '\0';
#ifdef DYNAMIC_DETECT
        if (recv_b > 0 || strlen(msg) > 0)
        {
            // len = -1 may be used for null terminated strings
            if (recv_b < 2)
                recv_b = (long)w_strlen(msg);

            // send message to detectmon
            detect_buffer_push(&msg[2], recv_b - 2);

            // skip ossec queue and location prefix, only match the message
            // <Queue>:<Location>:<Message>
            const char* message_loc = strchr(&msg[2], ':') + 1;
            const char* match_msg = message_loc ? message_loc : msg;
            const size_t match_len = (message_loc ? recv_b - (message_loc - msg) : recv_b) - 2;

            // check if the message should be discarded
            if (filter_log_check(match_msg, match_len) > 0)
            {
                b_filtered += recv_b;
                mdebug2("Filtered message: %s", msg);
                minfo("Filtered %ld B, sent %ld B", b_filtered, b_sent);
                continue;
            }
            b_sent += recv_b;
        }
#endif
        if (agt->buffer)
        {
            if (buffer_append(msg) < 0)
            {
                break;
            }
        }
        else
        {
            w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);

            if (send_msg(msg, -1) < 0)
            {
                break;
            }
        }
    }

    return (NULL);
}
