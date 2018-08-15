/*
 * Copyright (C) 2018 Ken Bannister <kb2ma@runbox.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_sock_tdsec   tinydtls sock security
 * @ingroup     net_sock
 *
 * @brief       Simple tinydtls-based DTLS adapter for sock
 *
 * tdsec provides a simple bridge for sock based communication to use tinydtls
 * for DTLS security. tdsec relies on tinydtls as much as possible to manage
 * the state and protocol for DTLS communication.
 *
 * For both server and client operation, RIOT automatically initializes the
 * library with tdsec_init() in the auto_init module. tdsec also expects the
 * presence of an application defined header file named tdsec_params.h. This
 * file contains the keys for security parameters specific to the chosen
 * cipher suite(s).
 *
 * The sections below describe server and client side use. See the RIOT
 * examples folder for an implementation, including tdsec_params.h.
 *
 * ## Server Operation
 *
 * A server application executes the following steps:
 *
 * tdsec_create() to create a tdsec reference object, which maintains the
 * connecting attributes between sock and tinydtls. All other uses of the
 * library must provide this object as a parameter. One of these parameters
 * is a tdsec_read_handler_t callback function for the received, decrypted
 * message from a client.
 *
 * sock_udp_recv() to wait on a DTLS handshake message from a remote client,
 * or an encrypted application message once the handshake has completed.
 *
 * tdsec_read() to process the received message. Behind the scenes, tinydtls
 * may ask to send messages to the client to complete the handshake. tinydtls
 * makes these requests via a callback, for which tdsec calls sock_udp_send().
 * Eventually tdsec calls the application's tdsec_read_handler_t callback
 * function, described above with tdsec_create(), with the decrypted data.
 *
 * This asynchronous approach to handling an incoming message supports
 * applications like gcoap that manage their own event loop. Other applications
 * require synchronous handling so that the decrypted message is returned by
 * the function that begins to listen for it. This synchronous handling is a
 * subject for future work.
 *
 * ## Client Operation
 *
 * A client application executes the following steps:
 *
 * tdsec_create() to create a tdsec reference object. See the description
 * above for server operation.
 *
 * tdsec_connect() to establish a DTLS connection with the server by
 * executing the sequence of messages in the handshake protocol. This function
 * waits for the exchange to complete or timeout.
 *
 * tdsec_send() to encrypt and send the provided message. First tdsec
 * encrypts the message based on cipher suite negotiated with the server. Then
 * it sends the encrypted message by calling sock_udp_send() internally.
 *
 * @{
 *
 * @file
 * @brief   tdsec definition
 *
 * @author  Ken Bannister <kb2ma@runbox.com>
 */

#ifndef NET_SOCK_TDSEC_H
#define NET_SOCK_TDSEC_H

#include "net/sock/udp.h"
#include "dtls.h"
#include "dtls_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Application handler function for decrypted incoming message
 */
typedef void (*tdsec_read_handler_t)(sock_udp_t *sock, uint8_t *data,
                                      size_t len, sock_udp_ep_t *remote);

/**
 * @brief   Root reference object for tdsec sock security
 */
typedef struct {
    sock_udp_t *sock;                   /**< UDP sock reference */
    dtls_context_t *td_context;         /**< tinydtls context object */
    tdsec_read_handler_t read_handler;  /**< Application callback for decrypted
                                             message */
} tdsec_ref_t;

/**
 * @brief PSK parameters
 */
typedef struct {
    const char *client_id;   /**< client identity */
    size_t id_len;           /**< length of client_id */ 
    const char *key;         /**< key itself */
    size_t key_len;          /**< length of key */ 
} tdsec_psk_params_t;


/**
 * @brief tinydtls initialization
 *
 * Must be called before any other use.
 */
void tdsec_init(void);

/**
 * @brief   Creates a tinydtls sock security object
 *
 * @return  0 on success
 */
int tdsec_create(tdsec_ref_t *tdsec, sock_udp_t *sock,
                 tdsec_read_handler_t read_handler);

/**
 * @brief   Establishes a connection/session with a remote endpoint for a DTLS
 *          client
 *
 * Waits up to 5 seconds for connection.
 *
 * @return >= 0 on success
 * @return < 0 on failure
 */
ssize_t tdsec_connect(tdsec_ref_t *tdsec, const sock_udp_ep_t *remote);

/**
 * @brief   Decrypts and reads a message from a remote peer
 *
 * Application data provided asynchronously by tdsec read_handler callback.
 */
ssize_t tdsec_read(tdsec_ref_t *tdsec, uint8_t *buf, size_t len,
                   const sock_udp_ep_t *remote);

/**
 * @brief   Encrypts and sends a message to a remote peer
 */
ssize_t tdsec_send(tdsec_ref_t *tdsec, const void *data, size_t len,
                   const sock_udp_ep_t *remote);

#ifdef __cplusplus
}
#endif

#endif /* NET_SOCK_TDSEC_H */
/** @} */
