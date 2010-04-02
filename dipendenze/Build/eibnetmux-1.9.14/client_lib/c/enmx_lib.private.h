/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2009 Urs Zurbuchen <going_nuts@users.sourceforge.net>
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
 *
 * \if DeveloperDocs
 *   \brief Library-private definitions and structures
 * \endif
 */
 
#ifndef ENMX_LIB_PRIVATE_H_
#define ENMX_LIB_PRIVATE_H_

/*!
 * \cond DeveloperDocs
 */

#include "../../eibnetmux/include/socketserver.h"
#include "../../eibnetmux/include/eibnetip.h"
/*
#ifdef ENMX_E_NO_ERROR
#undef ENMX_E_NO_ERROR
#endif
#ifdef ENMX_E_COMMUNICATION
#undef ENMX_E_COMMUNICATION
#endif
#ifdef ENMX_E_SERVER_ABORTED
#undef ENMX_E_SERVER_ABORTED
#endif
#ifdef ENMX_E_UNKNOWN_GROUP
#undef ENMX_E_UNKNOWN_GROUP
#endif
#ifdef ENMX_E_INTERNAL
#undef ENMX_E_INTERNAL
#endif
#ifdef ENMX_E_NO_MEMORY
#undef ENMX_E_NO_MEMORY
#endif
#ifdef ENMX_E_TIMEOUT
#undef ENMX_E_TIMEOUT
#endif
#ifdef ENMX_E_WRONG_USAGE
#undef ENMX_E_WRONG_USAGE
#endif
#ifdef ENMX_E_NO_CONNECTION
#undef ENMX_E_NO_CONNECTION
#endif
#ifdef ENMX_E_AUTH_UNSUPPORTED
#undef ENMX_E_AUTH_UNSUPPORTED
#endif
#ifdef ENMX_E_AUTH_FAILURE
#undef ENMX_E_AUTH_FAILURE
#endif
#ifdef ENMX_E_DHM_FAILURE
#undef ENMX_E_DHM_FAILURE
#endif
#ifdef ENMX_E_PARAMETER
#undef ENMX_E_PARAMETER
#endif
#ifdef ENMX_E_UNAUTHORISED
#undef ENMX_E_UNAUTHORISED
#endif
*/

#include "enmx_lib.h"

/*
 * constants
 */
#define ENMX_VERSION_API        4

// #define SOCKET_TCP_PORT                 4390
#define TIMEOUT                 3
#define ENMX_LIB_INITIALISED    0
#define ENMX_LIB_UNDEFINED     -1
#define ENMX_MODE_STANDARD      0
#define ENMX_MODE_PTH           1

#define ENMX_L7_MAXREPEAT       5
#define ENMX_L7_REPEAT_DELAY    3000


/*
 * EIB TPCI & APCI
 */
#define T_CONNECT_REQ_PDU                       0x80
#define T_CONNECT_CONF_PDU                      0x82
#define T_DISCONNECT_REQ_PDU                    0x81
#define T_DATA_REQ_PDU                          0x40
#define T_DATA_ACK_PDU                          0xc2
#define T_DATA_NAK_PDU                          0xc3
#define A_READ_PROPERTY_VALUE_REQ_PDU           0x03d5
#define A_READ_PROPERTY_VALUE_RES_PDU           0x03d6
#define A_WRITE_PROPERTY_VALUE_REQ_PDU          0x03d7
#define A_READ_PROPERTY_DESCRIPTION_REQ_PDU     0x03d8
#define A_READ_PROPERTY_DESCRIPTION_RES_PDU     0x03d9
#define A_UREAD_MEMORY_REQ_PDU                  0x02c0
#define A_UREAD_MEMORY_RES_PDU                  0x02c1
#define A_UWRITE_MEMORY_REQ_PDU                 0x02c2
#define A_UWRITE_MEMORY_BIT_REQ_PDU             0x02c4
#define A_UREAD_MFACTINFO_REQ_PDU               0x02c5
#define A_UREAD_MFACTINFO_RES_PDU               0x02c6
#define A_READ_ADC_REQ_PDU                      0x0180
#define A_READ_ADC_RES_PDU                      0x01c0
#define A_READ_MEMORY_REQ_PDU                   0x0200
#define A_READ_MEMORY_RES_PDU                   0x0240
#define A_WRITE_MEMORY_REQ_PDU                  0x0280
#define A_READ_MASK_VERSION_REQ_PDU             0x0300
#define A_READ_MASK_VERSION_RES_PDU             0x0340
#define A_RESTART_REQ_PDU                       0x0380
#define A_WRITE_MEMORY_BIT_REQ_PDU              0x03d0
#define A_AUTHORIZE_REQ_PDU                     0x03d1
#define A_AUTHORIZE_RES_PDU                     0x03d2
#define A_SETKEY_REQ_PDU                        0x03d3
#define A_SETKEY_RES_PDU                        0x03d4


/*
 * EIB priorities
 */
#define ENMX_PRIO_SYSTEM                        0
#define ENMX_PRIO_LOW                           3
#define ENMX_PRIO_HIGH                          1
#define ENMX_PRIO_ALARM                         2


/*
 * structures
 */
/*!
 * \addtogroup xgSetup
 * @{
 */
/*!
 * \brief socketserver client connection
 */
typedef struct _connInfo {
    int                     socket;         //!< unix socket client is connected on
    int                     errorcode;      //!< error code of last command
    int                     state;          //!< state of connection (see eConnectionState)
    char                    *hostname;      //!< hostname of client
    char                    *name;          //!< client identifier
    struct _connInfo        *next;          //!< link to next connection in linked list
    int                     mode;           //!< ENMX_MODE_STANDARD or ENMX_MODE_PTH
    int                     L7connection;   //!< >0 if layer 7 connection has been established with remote device
    int                     L7sequence_id;  //!< sequence id for layer 7 data requests/responses
    int                     (*send)( ENMX_HANDLE handle, unsigned char *buf, uint16_t length );                 //!< pointer to send function (standard or PTH)
    int                     (*recv)( ENMX_HANDLE handle, unsigned char *buf, uint16_t length, int timeout );    //!< pointer to receive function (standard or PTH)
    void                    (*wait)( int usec );    //!< pointer to wait function (standard or PTH)
} sConnectionInfo;

/*!
 * \brief EIBnet/IP search request
 * 
 * If a client wants to locate active EIBnet/IP servers on its subnet,
 * it sends an EIBnet/IP search request to an IP multicast address.
 * Active servers reply with an EIBnet/IP search response.
 */
typedef struct __attribute__((packed)) {
    uint8_t  headersize;                    //!< size of EIBnet/IP request header (6)
    uint8_t  version;                       //!< version of EIBnet/IP request header (10)
    uint16_t servicetype;                   //!< requested service type (0x0201)
    uint16_t totalsize;                     //!< total size of EIBnet/ip request
    uint8_t  structlength;                  //!< length of HPAI structure (8)
    uint8_t  hostprotocol;                  //!< hostprotocol used by searching client (1: IP v4 UDP, 2: IP v4 TCP)
    uint32_t ip;                            //!< IP address used by searching client
    uint16_t port;                          //!< UDP port searching client is listening on for replies
} EIBNETIP_SEARCH_REQUEST;


/*!
 * \brief connection state information
 */
typedef enum _eConnectionState {
    stateUnused,
    stateRead,
    stateWrite,
    stateMonitor,
    stateLayer7,
} eConnectionState;


/*
 * \brief layer 7 API parameters
 */
typedef struct __attribute__((packed)) {
    uint8_t  length;
    uint8_t  tpci;
    uint8_t  apci;
    uint8_t  priority;
} sLayer7Params;
/*! @} */


/*
 * globals
 */
extern sConnectionInfo         *enmx_connections;
extern int                      enmx_mode;

/*
 * function declarations
 */
extern int                  _enmx_send( ENMX_HANDLE handle, unsigned char *buf, uint16_t length );
extern int                  _enmx_receive( ENMX_HANDLE handle, unsigned char *buf, uint16_t length, int timeout );
extern void                 _enmx_wait( int msec );
extern int                  _enmx_pth_send( ENMX_HANDLE handle, unsigned char *buf, uint16_t length );
extern int                  _enmx_pth_receive( ENMX_HANDLE handle, unsigned char *buf, uint16_t length, int timeout );
extern void                 _enmx_pth_wait( int msec );
extern int                  _enmx_maperror( int code );
extern sConnectionInfo *    _enmx_connectionGet( ENMX_HANDLE handle );
extern int                  _enmx_connectionState( sConnectionInfo *pConn, int state );
extern int                  _enmx_L7Passthrough( sConnectionInfo *pConn, ENMX_ADDRESS knxaddress );
extern int                  _enmx_L7GetAckNak( sConnectionInfo *pConn );
extern int                  _enmx_L7State( sConnectionInfo *pConn );
extern int                  _enmx_L7Response( sConnectionInfo *connInfo, ENMX_ADDRESS knxaddress, unsigned char *buf, int *length, uint8_t tpci, uint16_t apci );


/*!
 * \endcond
 */
#endif /*ENMX_LIB_PRIVATE_H_*/
