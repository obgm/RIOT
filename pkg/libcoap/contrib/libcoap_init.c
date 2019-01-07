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
#include "xtimer.h"
#include "net/gnrc.h"
#include "net/udp.h"
#include "net/gnrc/netreg.h"

coap_context_t *coap_context = NULL;
kernel_pid_t coap_pid = KERNEL_PID_UNDEF;

static char _msg_stack[LIBCOAP_STACK_SIZE];
static msg_t _msg_q[LIBCOAP_MSG_QUEUE_SIZE];

static void _receive_coap(gnrc_pktsnip_t *pkt) {
    gnrc_pktsnip_t *udp;
    udp_hdr_t *udp_hdr;

    assert(pkt != NULL);

    udp = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_UDP);

    if (udp) {
        DEBUG("LIBCOAP: found UDP\n");
        udp_hdr = (udp_hdr_t *)udp->data;
        if (udp_hdr) {
            udp_hdr_print(udp_hdr);
        }
    }
}

static void *_event_loop(void *arg)
{
    gnrc_netreg_entry_t me_reg = { .demux_ctx = LIBCOAP_COAP_PORT,
                                   .target.pid = thread_getpid() };
    msg_t msg;
    (void)arg;

    msg_init_queue(_msg_q, LIBCOAP_MSG_QUEUE_SIZE);
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &me_reg);

    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            // FIXME: handle timeout
        case GNRC_NETAPI_MSG_TYPE_RCV:
            _receive_coap(msg.content.ptr);
            break;
        case GNRC_NETAPI_MSG_TYPE_SND:
            break;
        case GNRC_NETAPI_MSG_TYPE_SET:
            /* fall through */
        case GNRC_NETAPI_MSG_TYPE_GET:
            break;
        default:
            break;
        }
    }
    return NULL;
}

void libcoap_init(void)
{
    if (coap_pid != KERNEL_PID_UNDEF) {
        return;
    }

    coap_startup();
    coap_context = coap_new_context(NULL);

    coap_address_t addr;
    coap_address_init(&addr);
    addr.addr.sa.sa_family = AF_INET6;
    addr.addr.sin6.sin6_addr = in6addr_any;
    addr.addr.sin6.sin6_port = htons(COAP_DEFAULT_PORT);

    coap_endpoint_t *ep_udp;
    ep_udp = coap_new_endpoint(coap_context, &addr, COAP_PROTO_UDP);
    if (!ep_udp) {
        puts("Error creating CoAP UDP socket");
    }

    if (coap_context && ep_udp) {
        puts("CoAP context ready");
        coap_pid = thread_create(_msg_stack, sizeof(_msg_stack),
                                 THREAD_PRIORITY_MAIN - 1,
                                 THREAD_CREATE_STACKTEST,
                                 _event_loop, NULL, "coap_server");
    }
}

/** @} */
