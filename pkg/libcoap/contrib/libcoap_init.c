/*
 * Copyright (c) 2019 Olaf Bergmann. All rights reserved.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    pkg_libcoap  Libcoap
 * @ingroup     net
 * @brief       RIOT interface for libcoap
 *
 */

#include <errno.h>

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "thread.h"
#include "libcoap_init.h"
#include "net/gnrc.h"

void coap_riot_startup(void);

coap_context_t *coap_context = NULL;
kernel_pid_t coap_pid = KERNEL_PID_UNDEF;

static char _msg_stack[LIBCOAP_STACK_SIZE];

static void *_event_loop(void *arg)
{
    const unsigned int default_wait_time = COAP_RESOURCE_CHECK_TIME * 1000;
    unsigned wait_ms = default_wait_time;
    (void)arg;

    coap_riot_startup();

    while (1) {
        int result = coap_run_once(coap_context, wait_ms);
        if (result < 0) {
            break;
        } else if (result && (unsigned)result < wait_ms) {
            /* decrement if there is a result wait time returned */
            wait_ms -= result;
        } else {
            /*
             * result == 0, or result >= wait_ms
             * (wait_ms could have decremented to a small value, below
             * the granularity of the timer in coap_run_once() and hence
             * result == 0)
             */
        }
        if (result) {
            /* result must have been >= wait_ms, so reset wait_ms */
            wait_ms = default_wait_time;
        }
    }

    /* never reached */
    return NULL;
}

void libcoap_init(void)
{
    if (coap_pid != KERNEL_PID_UNDEF) {
        return;
    }

    coap_startup();
    coap_context = coap_new_context(NULL);
    if (!coap_context) {
        puts("Error creating CoAP context");
        return;
    }

    /* TODO: create CoAP endpoints for each interface. */
    bool ok = false;
    coap_address_t addr;
    coap_address_init(&addr);
    addr.addr.sa.sa_family = AF_INET6;
    addr.addr.sin6.sin6_addr = in6addr_any;
    addr.addr.sin6.sin6_port = htons(LIBCOAP_COAP_PORT);

    ok = coap_new_endpoint(coap_context, &addr, COAP_PROTO_UDP) || ok;

    addr.addr.sin6.sin6_port = htons(LIBCOAP_COAPS_PORT);
    ok = coap_new_endpoint(coap_context, &addr, COAP_PROTO_UDP) || ok;

    if (!ok) {
        puts("Error creating CoAP endpoints");
        coap_free_context(coap_context);
        coap_cleanup();
        coap_context = NULL;
        return;
    }

    if (coap_context && ok) {
        puts("CoAP context ready");
        coap_pid = thread_create(_msg_stack, sizeof(_msg_stack),
                                 THREAD_PRIORITY_MAIN - 1,
                                 THREAD_CREATE_STACKTEST,
                                 _event_loop, NULL, "coap_server");
    }
}

/** @} */
