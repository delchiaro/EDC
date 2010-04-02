/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2008 Urs Zurbuchen <going_nuts@users.sourceforge.net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
 
#ifndef SOCKETSERVER_H_
#define SOCKETSERVER_H_

#ifdef WITH_AUTHENTICATION
#include <polarssl/dhm.h>
#endif

#include "socketserver.h"

/********************************/
/* Constants and structures     */
/********************************/

/**
 * configuration socket server
 **/
#define SOCKETS_MAX                     20


/**
 * timeout constants in seconds
 **/
#define SOCKET_REQ_TIMEOUT              15
#define CONNECT_READ_TIMEOUT            30


/**
 * structures
 **/
typedef struct _SOCKET_INFO {
    uint32_t        connectionid;                   // unique connection id
    int             socket;                         // if no connection, socket = 0
    uint8_t         type;                           // none, write, read, monitor, passthrough
    uint8_t         status;                         // indicate error with connection, should be E_NO_ERROR.
    unsigned int    knxaddress;                     // knx individual address assigned to connection
    uint16_t        pdu_resp;                       // expected response pdu (tpci & apci)
    uint16_t        pdu_mask;                       // bits of expected response pdu (tpci & apci) which need to match
    uint8_t         response_outstanding;           // true if next group address packet needs to be forwarded to client
    pth_t           threadid;                       // id of handler thread for this connection
    uint32_t        statsPacketsReceived;           // number of packets received on this connection
    uint32_t        statsPacketsSent;               // number of packets sent to this connection
    char            *name;                          // client identifier
    sSecurityUser   *user;                          // authenticated user
    auth_t          authorisation;                  // current user's function mask for authorisation
#ifdef WITH_AUTHENTICATION
    dhm_context     *p_dhm;                         // diffie-hellman-merkle information
#endif
    unsigned char   *key;                           // encryption key used for this connection
    struct _SOCKET_INFO     *next;                  // pointer to next socket in list
} SOCKET_INFO;


typedef struct __attribute__((packed)) {
    uint8_t  length;
    uint8_t  tpci;
    uint8_t  apci;
    uint8_t  priority;
} sPassthroughParams;


/*
 * function declarations
 */


/*
 * global variables
 */
extern SOCKET_INFO              *socketcon;

#endif /*SOCKETSERVER_H_*/
