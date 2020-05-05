/*
 * Copyright (C) 2019 Olaf Bergmann <bergmann@tzi.org>
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
 * @brief       Demonstrating CoAP requests with libcoap.
 *
 * @author      Olaf Bergmann <bergmann@tzi.org>
 *
 * @}
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libcoap_init.h"

static void response_handler(coap_context_t *context,
                             coap_session_t *session,
                             coap_pdu_t *sent,
                             coap_pdu_t *received,
                             const coap_tid_t id) {
    (void)context;
    (void)sent;
    (void)received;
    (void)id;
    coap_session_release(session);
}


int coap_client(int argc, char **argv)
{
    const char *methods[] =
        { 0, "get", "post", "put", "delete", "fetch", "patch", "ipatch", 0};
    int method;
    coap_address_t src, dst;

    if (argc < 3) {
        printf("usage: %s method URI\n", argv[0]);
        return 1;
    }

    /* parse method from first argument */
    for (method=1; methods[method]; method++) {
        if (strcasecmp(argv[1], methods[method]) == 0) {
            break;
        }
    }
    if (!method) {
        printf("Error: unknown CoAP method '%s'\n", argv[1]);
        return 1;
    }
    
    coap_uri_t uri;
    if (coap_split_uri((uint8_t *)argv[2], strlen(argv[2]), &uri) != 0) {
        printf("invalid CoAP URI '%s'\n", argv[2]);
        return 1;        
    }

    coap_address_init(&src);
    coap_address_init(&dst);
    char addr_str[INET6_ADDRSTRLEN + 1];
    if (uri.host.length >= sizeof(addr_str)) {
        puts("Error: cannot store hostname");
        return 1;
    }
    memset(addr_str, 0, sizeof(addr_str));
    memcpy(addr_str, uri.host.s, uri.host.length);

    dst.size = sizeof(dst.addr.sin6);
    dst.addr.sa.sa_family = AF_INET6;
    dst.addr.sin6.sin6_port = htons(uri.port);
    /* parse destination address */
    if (inet_pton(AF_INET6, addr_str, &dst.addr.sin6.sin6_addr) != 1) {
        puts("Error: unable to parse destination address");
        return 1;
    }

    coap_session_t *session;
    coap_pdu_t *request;

    gnrc_netif_t *netif = NULL;
    ipv6_addr_t ipv6_addrs[CONFIG_GNRC_NETIF_IPV6_ADDRS_NUMOF];
    while ((netif = gnrc_netif_iter(netif))) {
        int res = gnrc_netapi_get(netif->pid, NETOPT_IPV6_ADDR, 0, ipv6_addrs,
                                  sizeof(ipv6_addrs));

        if (res > 0) {
            src.size = sizeof(src.addr.sin6);
            src.addr.sin6.sin6_family = AF_INET6;
            src.addr.sin6.sin6_port = 0;
            memcpy(&src.addr.sin6.sin6_addr,
                   &ipv6_addrs[0],
                   sizeof(ipv6_addr_t));
            break;
        }
    }

    if (uri.scheme == COAP_URI_SCHEME_COAPS) {
        session = coap_new_client_session_psk(coap_context,
                                              NULL,
                                              &dst,
                                              COAP_PROTO_DTLS,
                                              "CoAP", NULL, 0);
    } else {
        session = coap_new_client_session(coap_context,
                                          &src,
                                          &dst,
                                          COAP_PROTO_UDP);
    }
    if (!session) {
        puts("Error: cannot create CoAP session");
        return 1;
    }

    /* Fill a new CoAP PDU with method and options. */
    request = coap_new_pdu(session);
    if (!request) {
        puts("Error: cannot create CoAP request");
        coap_session_release(session);
        return 1;
    }
    request->tid = coap_new_message_id(session);
    request->code = method;

    coap_optlist_t *options = NULL;
    if (uri.path.length) {
        unsigned char buf[64];
        unsigned char *p = buf;
        size_t buflen = sizeof(buf);
        int res;

        res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
        while (res--) {
            coap_insert_optlist(&options,
                                coap_new_optlist(COAP_OPTION_URI_PATH,
                                                 coap_opt_length(p),
                                                 coap_opt_value(p)));
            p += coap_opt_size(p);
        }
    }

    coap_add_optlist_pdu(request, &options);

    /* Register a response handler to clear session after receipt of a
     * response. */
    coap_register_response_handler(session->context, response_handler);

    /* And send the request. */
    coap_send(session, request);
    return 1;
}

