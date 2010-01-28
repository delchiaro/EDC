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
 
#ifndef EIBNETIP_H_
#define EIBNETIP_H_

#include <pth.h>

#include "eibnetip.h"

/********************************/
/* Constants and structures     */
/********************************/

/**
 * configuration EIBNET/IP side
 **/
#define EIBNETIP_MAXCONNECTIONS                 31
typedef uint32_t                                connmask_t;             // must be at least EIBNETIP_MAXCONNECTIONS +1 bits
#define ADDITIONAL_INDIVIDUAL_ADDRESSES_NR      1
#define FRIENDLY_NAME                           "eibnetmux"
#define CONFIG_KNXMEDIUM                        TP0
#define CONFIG_SN0                              0x00
#define CONFIG_SN1                              0x01
#define CONFIG_SN2                              0x11
#define CONFIG_SN3                              0x11
#define CONFIG_SN4                              0x11
#define CONFIG_SN5                              0x11
#define EIBNETIP_FRAME_SIZE                     0x40
#define PROJECT_INSTALLATION_ID                 0
#define MAX_RESENDS                             3

/*
 * EIB frame constants
 */
#define EIB_CTRL_LENGTHTABLE                    0x00
#define EIB_CTRL_LENGTHBYTE                     0x80
#define EIB_CTRL_DATA                           0x00
#define EIB_CTRL_POLL                           0x40
#define EIB_CTRL_REPEAT                         0x00
#define EIB_CTRL_NOREPEAT                       0x20
#define EIB_CTRL_ACK                            0x00
#define EIB_CTRL_NONACK                         0x10
#define EIB_CTRL_PRIO_LOW                       0x0c
#define EIB_CTRL_PRIO_HIGH                      0x04
#define EIB_CTRL_PRIO_ALARM                     0x08
#define EIB_CTRL_PRIO_SYSTEM                    0x00
#define EIB_NETWORK_HOPCOUNT                    0x70
#define EIB_DAF_GROUP                           0x80
#define EIB_DAF_PHYSICAL                        0x00
#define EIB_LL_NETWORK                          0x70
#define T_GROUPDATA_REQ                         0x00
#define A_READ_VALUE_REQ                        0x0000
#define A_WRITE_VALUE_REQ                       0x0080

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


/**
 * system selection constants
 */
#define EIBNETIP_SERVER                         logModuleEIBnetServer
#define EIBNETIP_CLIENT                         logModuleEIBnetClient


/**
 * queue pending bit selection
 */
#define QUEUE_PENDING_SOCKET                    0x01
#define QUEUE_PENDING_EIBD                      0x02


typedef enum _eLoopback {
    loopbackUndefined,
    loopbackOff,
    loopbackOn,
} eLoopback;


/**
 * structures
 **/
typedef struct {
    uint32_t    connectionid;               // unique connection id
    uint8_t     channelid;                  // channelid is always > 0 and <= EIBNET_MAXCONNECTIONS
    uint8_t     sequencecounter_rcv;
    uint8_t     sequencecounter_sent;
    uint8_t     connectiontype;             // tunneling, routing, ...
    time_t      lastHeartBeat;              // time when server received last heartbeat
    uint8_t     status;                     // indicate error with connection, should be E_NO_ERROR.
    EIBNETIP_HPAI hpai;                     // channel endpoint of connected client
    //uint8_t version;                      // protocol version, currently not needed
    uint8_t     connectioninfo;             // additional information -> f.e. tunneling layer
    unsigned int knxaddress;                // knx individual address assigned to connection
    eLoopback   loopback;                   // loopback mode where EIBnetmux' client connects to its own einet/ip server
    uint32_t    ipSource;                   // ip address used as source for this connection
    uint16_t    ipPort;                     // udp port used as source for this connection
    uint8_t     counter;                    // number of times current request was sent & resent
    time_t      nextsend;                   // next time current request needs to be re-sent to connected clients (in seconds)
    pth_t       threadid;                   // id of forwarded thread for this connection
    pth_cond_t  *condResponse;              // used to signal sender that response has arrived
    pth_mutex_t *mtxResponse;
    uint32_t    statsPacketsReceived;       // number of packets received on this connection
    uint32_t    statsPacketsSent;           // number of packets sent to this connection
} EIBNETIP_CONNECTION;

typedef struct _EIBNETIP_QUEUE {
        uint32_t        nr;                 // sequential number of reqeuest as it is received
        uint8_t         *data;              // pointer to tunneldata
        uint16_t        len;                // length of tunneldata
        connmask_t      pending_eibnet;
        uint32_t        pending_others;
        // uint16_t        servicetype;
        struct _EIBNETIP_QUEUE  *next;      // pointer to next tunnel request packet
} EIBNETIP_QUEUE;


/*
 * EIBnet/IP tunneling client state
 */
typedef enum _eEIBstate {
        eibnetTunnelConnected = 5,
        eibnetTunnelClosed,
        eibnetTunnelShutdown,
} eEIBstate;


/*
 * function declarations
 */
// common.c
extern void             initEIBframe( EIBFRAME* ef, uint8_t priority, uint16_t sadr, uint16_t destadr, uint8_t daf, uint8_t service_type, uint8_t* data, uint8_t length );
extern void             extractCemi( CEMI_L_DATA_MESSAGE *emi, uint8_t *rcvdata );
extern void             initEIBframeCemi( EIBFRAME* ef, CEMI_L_DATA_MESSAGE *cemi );
extern void             initCemiframe( CEMI_L_DATA_MESSAGE *cemi, EIBFRAME *ef );
extern void             eibNetClearConnection( EIBNETIP_CONNECTION *conn );
extern void             setupSignalling( void *module, uint8_t channelid );
extern void             releaseSignalling( uint8_t channelid );
extern void             eibNetIpSend( void *module, int sock, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size );
extern int              eibNetIpSendControl( void *system, EIBNETIP_CONNECTION *conn, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size );
extern int              eibNetIpSendData( void *system, EIBNETIP_CONNECTION *conn, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size );
extern EIBNETIP_QUEUE * removeRequestFromQueue( void *module, EIBNETIP_QUEUE *queue );
extern void             addRequestToQueue( void *system, EIBNETIP_QUEUE **top, unsigned char *buf, int len );

// eibnetip.c
extern int              EIBnetIPProtocolHandler( void *system, uint8_t *rcvdata, uint16_t rcvdatalen, eSecAddrType secType );

/*
 * global variables
 */
extern EIBNETIP_QUEUE          *eibQueueClient;
extern EIBNETIP_QUEUE          *eibQueueServer;
extern EIBNETIP_QUEUE          *eibQueueSocket;
extern EIBNETIP_CONNECTION     eibcon[];
extern int                     sock_eibclient_control;
extern int                     sock_eibclient_data;
extern int                     sock_eibserver;

#endif /*EIBNETIP_H_*/
