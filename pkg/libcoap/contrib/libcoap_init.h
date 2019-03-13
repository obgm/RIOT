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

#ifndef PKG_LIBCOAP_H
#define PKG_LIBCOAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "coap.h"

/**
 * @brief libcoap thread stack size
 */
#ifndef LIBCOAP_STACK_SIZE
#define LIBCOAP_STACK_SIZE (THREAD_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE \
                            + COAP_DEFAULT_MAX_PDU_RX_SIZE)
#endif /* LIBCOAP_STACK_SIZE */

#ifndef LIBCOAP_COAP_PORT
#define LIBCOAP_COAP_PORT (5683U)
#endif /* LIBCOAP_COAP_PORT */

#ifndef LIBCOAP_COAPS_PORT
#define LIBCOAP_COAPS_PORT (5684U)
#endif /* LIBCOAP_COAPS_PORT */

/**
 * @brief  The global CoAP context.
 *
 * This variable is set to the global libcoap
 * context by libcoap_init(). On error, its value
 * will be NULL.
 */
extern coap_context_t *coap_context;

/**
 * @brief  The process id of the CoAP server.
 *
 * This variable is set to the thread running the
 * main coap server. In case the thread could not
 * be started, its value is KERNEL_PID_UNDEF.
 */
extern kernel_pid_t coap_pid;

/**
 * @brief   Initializes the libcoap thread and context
 *
 * This function must be called once before first use,
 * typically from auto_init.
 */
void libcoap_init(void);

#ifdef __cplusplus
}
#endif

#endif /* PKG_LIBCOAP_H */
/** @} */
