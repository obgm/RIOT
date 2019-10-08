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
 * @brief       Example application for demonstrating libcoap and DTLS
 *
 * @author      Olaf Bergmann <bergmann@tzi.org>
 *
 * @}
 */

#include <stdio.h>

#include "msg.h"
#include "shell.h"
#include "thread.h"
#include "net/gnrc/netif.h"

#include "libcoap_init.h"

static const int coap_log_level = LOG_DEBUG;

#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */
#define MAX_RESOURCE_BUF 128

static const char r_hello[] = "hello";
static char resource_buf[MAX_RESOURCE_BUF] =
    "Hello World\n";
static size_t resource_len = 12;

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
    response->code = COAP_RESPONSE_CODE(205);

    coap_add_option(response,
                    COAP_OPTION_CONTENT_TYPE,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         COAP_MEDIATYPE_TEXT_PLAIN),
                    buf);

    coap_add_data(response, resource_len, (const uint8_t *)resource_buf);
}

static void init_resources(coap_context_t *ctx)
{
    coap_resource_t *r;
    r = coap_resource_init(coap_make_str_const(r_hello), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
    coap_add_resource(ctx, r);
}

int set_psk(int argc, char **argv)
{
    if (argc < 2) {
      printf("usage: %s string\n", argv[0]);
    } else {
        coap_context_set_psk(coap_context,
                             NULL,
                             (uint8_t *)argv[1],
                             strlen(argv[1]));
    }
    return 1;
}

extern int coap_client(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "psk", "set default pre-shared key for CoAP over DTLS communication", set_psk },
    { "coap", "send CoAP request", coap_client },
    { NULL, NULL, NULL }
};

int main(void)
{
    puts("CoAP example server using libcoap");

    assert(coap_context != NULL);
    init_resources(coap_context);
    coap_set_log_level(coap_log_level);
    coap_dtls_set_log_level(coap_log_level);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
