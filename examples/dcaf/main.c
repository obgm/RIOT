/*
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating DCAF package
 *
 * @author      Olaf Bergmann <bergmann@tzi.org>
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "msg.h"
#include "thread.h"
#ifdef MODULE_SHELL
#include "shell.h"
#endif /* MODULE_SHELL */

#include "libcoap_init.h"
#include "coap2/coap.h"

#ifdef MODULE_DCAF
#include "dcaf/dcaf.h"
#endif /* MODULE_DCAF */

dcaf_config_t dcaf_config = {
                             .am_uri = "coaps://am.libcoap.net:7744/authorize"
                             /* do not set host, coap_port and coaps_port here */
};

static const int coap_log_level = LOG_DEBUG;
static const int dcaf_log_level = LOG_DEBUG;

#define MAIN_MSG_QUEUE_SIZE (4)
static msg_t main_msg_queue[MAIN_MSG_QUEUE_SIZE];

#ifdef MODULE_SHELL
extern int udp_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
                                                 { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
                                                 { NULL, NULL, NULL }
};
#endif /* MODULE_SHELL */

#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */
#define MAX_RESOURCE_BUF 128

static const char r_restricted[] = "restricted";
static char resource_buf[MAX_RESOURCE_BUF] =
    "This is a resource with restricted access.\n";
static size_t resource_len = 43;

/* handler for requests to a resource with restricted access */
static void
hnd_get(coap_context_t *ctx,
        struct coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query,
        coap_pdu_t *response) {
    unsigned char buf[3];
    (void)ctx;
    (void)resource;
    (void)token;
    (void)query;
    (void)session;
    (void)request;
#ifdef MODULE_DCAF
    /* Check if authorized, i.e., the request was received on a secure
     * channel. */
    if (!dcaf_is_authorized(session, request)) {
        dcaf_result_t res;
        res = dcaf_set_sam_information(session, DCAF_MEDIATYPE_DCAF_CBOR,
                                       response);
        if (res != DCAF_OK) {
            coap_log(LOG_WARNING, "cannot create SAM Information %d\n", res);
        }
        return;
    }
#endif /* MODULE_DCAF */
    response->code = COAP_RESPONSE_CODE(205);

    coap_add_option(response,
                    COAP_OPTION_CONTENT_TYPE,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         COAP_MEDIATYPE_TEXT_PLAIN),
                    buf);

    coap_add_data(response, resource_len, (const uint8_t *)resource_buf);
}

static void
init_resources(coap_context_t *ctx) {
    coap_resource_t *r;
    /* initialize the resource for uploading tickets */
    r = coap_resource_init(coap_make_str_const(r_restricted), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
    coap_add_resource(ctx, r);
}

int main(void)
{
    dcaf_context_t *dcaf;
    /* a sendto() call performs an implicit bind(), hence, a message queue is
     * required for the thread executing the shell */
    msg_init_queue(main_msg_queue, MAIN_MSG_QUEUE_SIZE);
    puts("DCAF example server");
    assert(coap_context != NULL);
    init_resources(coap_context);
    coap_set_log_level(coap_log_level);
    dcaf_set_log_level(dcaf_log_level);

    /* set random number generator function for DCAF library */
    /* dcaf_set_prng(rnd); */

    dcaf = dcaf_new_context(&dcaf_config);
    if (!dcaf)
        return 2;

#ifdef MODULE_SHELL
    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
#else /* MODULE_SHELL */
    while (true) {
        thread_yield();
    }
#endif /* MODULE_SHELL */
    /* should be never reached */
    return 0;
}
