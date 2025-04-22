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
#include "detect/detect.h"
#include "os_net/os_net.h"
#include "sec.h"
#include "shared.h"

#ifdef DYNAMIC_DETECT
#include "detect/detect.h"
#include "filter.h"
#endif

/* Receive a message locally on the agent and forward it to the manager */
void* EventForward()
{
#ifdef DYNAMIC_DETECT
    detect_rule_t** discard_rules = filter_init(NULL);
    if (discard_rules == NULL)
    {
        merror("Failed to initialize filter rules");
        mwarn("Proceeding without filter rules");
    }
#endif

    ssize_t recv_b;
    char msg[OS_MAXSTR + 1];

    /* Initialize variables */
    msg[0] = '\0';
    msg[OS_MAXSTR] = '\0';

    while ((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
    {
        msg[recv_b] = '\0';
        if (agt->buffer)
        {
#ifdef DYNAMIC_DETECT
            // send message to detectmon
            detect_buffer_push(msg, recv_b);

            // check if the message should be discarded
            if (filter_log_check(discard_rules, msg, recv_b) > 0)
            {
                continue;
            }
#endif
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
