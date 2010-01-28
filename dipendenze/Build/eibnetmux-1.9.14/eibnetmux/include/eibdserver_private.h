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
 
#ifndef EIBDSERVER_H_
#define EIBDSERVER_H_

#include <stdint.h>

#include "eibtypes.h"

/********************************/
/* Constants and structures     */
/********************************/

/**
 * configuration socket server
 **/
#define EIBDCLIENTS_MAX                 32
#define EIBD_TCP_PORT                   6720



/**
 * timeout constants in seconds
 **/
#define EIBD_REQ_TIMEOUT                15
#define EIBD_READ_TIMEOUT               30


/*
 * EIBD constants
 */
#define EIBD_VIRGIN_CONNECTION          0xffff


/**
 * structures
 **/
typedef struct __attribute__((packed)) {
    uint16_t        size;
    uint16_t        command;                        // command code
} EIBD_CMD_HEAD;

typedef struct __attribute__((packed)) {
    uint16_t        knxaddress;                     // knx address, format 0mmm msss gggg gggg
    uint8_t         writeonly;                      // set if connection is write-only
} EIBD_CMD_PARAM;

typedef struct __attribute__((packed)) {
    uint16_t        size;
    uint16_t        command;
    uint16_t        source;
    unsigned char   data[20];
} EIBD_RESP_APDU;

typedef struct __attribute__((packed)) {
    uint16_t        size;
    uint16_t        command;
    uint16_t        source;
    uint16_t        destination;
    unsigned char   data[20];
} EIBD_RESP_GROUP;

typedef struct __attribute__((packed)) {
    uint16_t        size;
    uint16_t        command;
    uint8_t         control;
    uint16_t        source;
    uint16_t        dest;
    uint8_t         network;
    unsigned char   data[16];
} EIBD_RESP_BUSMON_SMALL;

typedef struct __attribute__((packed)) {
    uint16_t        size;
    uint16_t        command;
    uint8_t         control;
    uint8_t         network;
    uint16_t        source;
    uint16_t        dest;
    uint8_t         length;
} EIBD_RESP_BUSMON_LARGE;

typedef struct _EIBD_INFO {
    uint32_t        connectionid;                   // unique connection id
    int             socket;                         // if no connection, socket = 0
    uint16_t        type;                           // connection type (busmonitor, group socket, ...)
    uint16_t        valid_command;                  // valid command for this connection type
    int             writeonly;                      // set if connection is write-only
    uint8_t         status;                         // indicate error with connection, should be E_NO_ERROR.
    unsigned int    knxaddress;                     // knx individual address assigned to connection
    uint8_t         response_outstanding;           // true if next group address packet needs to be forwarded to client
    pth_t           threadid;                       // id of handler thread for this connection
    uint32_t        statsPacketsReceived;           // number of packets received on this connection
    uint32_t        statsPacketsSent;               // number of packets sent to this connection
    auth_t          authorisation;                  // current user's function mask for authorisation
    struct _EIBD_INFO     *next;                  // pointer to next socket in list
} EIBD_INFO;


/*
 * function declarations
 */


/*
 * global variables
 */
extern EIBD_INFO              *eibdcon;

#endif /*EIBDSERVER_H_*/
