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
 * threads
 *   EIBDListener          receive connection requests from tcp/ip socket clients
 *   EIBDHandler      spawned for each connection established by SocketServer which sends requests to bus
 *   eibdFromBus      one thread forwarding group address requests to appropriate clients
 *
 * eibd-compatible server 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <features.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibdserver_private.h"
#include "include/eibnetip_private.h"
#include "include/eibtypes.h"

#define  THIS_MODULE    logModuleEIBDServer

/*
 * Globals
 */
EIBD_INFO               *eibdcon = NULL;            // saves all active connections
int                     eibd_server = 0;            // tcp socket for communication with eibd clients
pth_cond_t              condQueueEIBD;              // signals tunneling forwarder on pending requests
pth_mutex_t             mtxEIBDForwarder;           // make sure forwarder is only started once


/*
 * Local types
 */
typedef struct _sThreadArgs {
    int                 sock;
    eSecAddrType        auth;
    struct sockaddr_in  client;
    uint32_t            rule;
} sThreadArgs;
typedef struct _sCmdNames {
    int             command;
    char            *name;
} sCmdNames;


/*
 * Local variables
 */
static pth_t            tid_eibd = 0;
static pth_t            tid_forward = 0;
static pth_mutex_t      mtxQueueEIBD;
static uint32_t         statsTotalSent = 0;                     // statistics
static uint32_t         statsTotalReceived = 0;

static sCmdNames        eibdCmdNames[] = {
                                            { EIB_INVALID_REQUEST, "EIB_INVALID_REQUEST" },
                                            { EIB_CONNECTION_INUSE, "EIB_CONNECTION_INUSE" },
                                            { EIB_PROCESSING_ERROR, "EIB_PROCESSING_ERROR" },
                                            { EIB_CLOSED, "EIB_CLOSED" },
                                            { EIB_RESET_CONNECTION, "EIB_RESET_CONNECTION" },
                                    
                                            { EIB_OPEN_BUSMONITOR, "EIB_OPEN_BUSMONITOR" },
                                            { EIB_OPEN_BUSMONITOR_TEXT, "EIB_OPEN_BUSMONITOR_TEXT" },
                                            { EIB_OPEN_VBUSMONITOR, "EIB_OPEN_VBUSMONITOR" },
                                            { EIB_OPEN_VBUSMONITOR_TEXT, "EIB_OPEN_VBUSMONITOR_TEXT" },
                                            { EIB_BUSMONITOR_PACKET, "EIB_BUSMONITOR_PACKET" },
                                    
                                            { EIB_OPEN_T_CONNECTION, "EIB_OPEN_T_CONNECTION" },
                                            { EIB_OPEN_T_INDIVIDUAL, "EIB_OPEN_T_INDIVIDUAL" },
                                            { EIB_OPEN_T_GROUP, "EIB_OPEN_T_GROUP" },
                                            { EIB_OPEN_T_BROADCAST, "EIB_OPEN_T_BROADCAST" },
                                            { EIB_OPEN_T_TPDU, "EIB_OPEN_T_TPDU" },
                                            { EIB_APDU_PACKET, "EIB_APDU_PACKET" },
                                            { EIB_OPEN_GROUPCON, "EIB_OPEN_GROUPCON" },
                                            { EIB_GROUP_PACKET, "EIB_GROUP_PACKET" },
                                    
                                            { EIB_PROG_MODE, "EIB_PROG_MODE" },
                                            { EIB_MASK_VERSION, "EIB_MASK_VERSION" },
                                            { EIB_M_INDIVIDUAL_ADDRESS_READ, "EIB_M_INDIVIDUAL_ADDRESS_READ" },
                                    
                                            { EIB_M_INDIVIDUAL_ADDRESS_WRITE, "EIB_M_INDIVIDUAL_ADDRESS_WRITE" },
                                            { EIB_ERROR_ADDR_EXISTS, "EIB_ERROR_ADDR_EXISTS" },
                                            { EIB_ERROR_MORE_DEVICE, "EIB_ERROR_MORE_DEVICE" },
                                            { EIB_ERROR_TIMEOUT, "EIB_ERROR_TIMEOUT" },
                                            { EIB_ERROR_VERIFY, "EIB_ERROR_VERIFY" },
                                    
                                            { EIB_MC_CONNECTION, "EIB_MC_CONNECTION" },
                                            { EIB_MC_READ, "EIB_MC_READ" },
                                            { EIB_MC_WRITE, "EIB_MC_WRITE" },
                                            { EIB_MC_PROP_READ, "EIB_MC_PROP_READ" },
                                            { EIB_MC_PROP_WRITE, "EIB_MC_PROP_WRITE" },
                                            { EIB_MC_PEI_TYPE, "EIB_MC_PEI_TYPE" },
                                            { EIB_MC_ADC_READ, "EIB_MC_ADC_READ" },
                                            { EIB_MC_AUTHORIZE, "EIB_MC_AUTHORIZE" },
                                            { EIB_MC_KEY_WRITE, "EIB_MC_KEY_WRITE" },
                                            { EIB_MC_MASK_VERSION, "EIB_MC_MASK_VERSION" },
                                            { EIB_MC_RESTART, "EIB_MC_RESTART" },
                                            { EIB_MC_WRITE_NOVERIFY, "EIB_MC_WRITE_NOVERIFY" },
                                            { EIB_MC_PROG_MODE, "EIB_MC_PROG_MODE" },
                                            { EIB_MC_PROP_DESC, "EIB_MC_PROP_DESC" },
                                            { EIB_MC_PROP_SCAN, "EIB_MC_PROP_SCAN" },
                                            { EIB_LOAD_IMAGE, "EIB_LOAD_IMAGE" },
                                    
                                            { EIB_CACHE_ENABLE, "EIB_CACHE_ENABLE" },
                                            { EIB_CACHE_DISABLE, "EIB_CACHE_DISABLE" },
                                            { EIB_CACHE_CLEAR, "EIB_CACHE_CLEAR" },
                                            { EIB_CACHE_REMOVE, "EIB_CACHE_REMOVE" },
                                            { EIB_CACHE_READ, "EIB_CACHE_READ" },
                                            { EIB_CACHE_READ_NOWAIT, "EIB_CACHE_READ_NOWAIT" },
                                            { -1, "<unknown>" }             // must be last entry
};


/*
 * local function declarations
 */
static void     eibdClearConnection( uint8_t clientid );
static void     eibdTerminateConnection( int clientid );
static int      eibdGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold );
static void     eibdSendResponse( int clientid, uint16_t code );
static void     eibdSendPacket( int clientid, unsigned char *buf, int length );
static void     eibdFlushRest( int clientid, int length );
static char     *eibdGetCommandName( int command );
static void     serverShutdown( void );


/*
 * eibdClearConnection
 * 
 * reset socket information
 */
static void eibdClearConnection( uint8_t clientid ) 
{
    if( clientid >= config.eibdclients ) {
        return;
    }
    
    eibdcon[clientid].connectionid         = 0;
    eibdcon[clientid].socket               = 0;
    eibdcon[clientid].type                 = 0;
    eibdcon[clientid].status               = E_NO_ERROR;
    eibdcon[clientid].response_outstanding = false;
    eibdcon[clientid].threadid             = 0;
    eibdcon[clientid].knxaddress           = 0;
    eibdcon[clientid].statsPacketsSent     = 0;
    eibdcon[clientid].statsPacketsReceived = 0;
}


/*
 * Close socket connection with connection id
 */
/*
static int eibdCloseConnection( uint32_t connectionid )
{
    int     loop;
    
    for( loop = 0; loop < config.eibdclients; loop++ ) {
        if( eibdcon[loop].socket != 0 && eibdcon[loop].connectionid == connectionid ) {
            logDebug( THIS_MODULE, "Found slot %d for connection id %d", loop, connectionid );
            if( eibdcon[loop].threadid != 0 ) pth_abort( eibdcon[loop].threadid );
            close( eibdcon[loop].socket );
            eibdClearConnection( loop );
            return( 0 );
        }
    }
    
    return( -1 );
}
*/


/*
 * terminateConnection
 * 
 * closes socket connection and terminates handler thread
 */
static void eibdTerminateConnection( int clientid )
{
    if( clientid >= config.eibdclients ) {
        return;
    }
    
    close( eibdcon[clientid].socket );
    eibdClearConnection( clientid );
    pth_exit( NULL );
}


/**
 * Return list of all allocated connection ids
 **/
static int eibdGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold )
{
    int     loop;
    
    array = allocMemory( system, config.eibdclients * sizeof( uint32_t ));
    for( loop = 0; loop < config.eibdclients; loop++ ) {
        if( eibdcon[loop].socket != 0 && eibdcon[loop].connectionid > threshold ) {
            *array[entries++] = eibdcon[loop].connectionid;
        }
    }
    return( entries );
}


/**
 * Return name of command
 */
static char *eibdGetCommandName( int command )
{
    int     idx;
    
    for( idx = 0; eibdCmdNames[idx].command != -1; idx++ ) {
        if( eibdCmdNames[idx].command == command ) {
            break;
        }
    }
    
    return( eibdCmdNames[idx].name );
}


/*
 * returnResult
 * 
 * send acknowledgement or error to socket client
 */
static void eibdSendResponse( int clientid, uint16_t code )
{
    unsigned char   response[4];
    char            *hdump;
    
    if( clientid >= config.eibdclients ) {
        return;
    }
    
    response[0] = 0;
    response[1] = 2;
    response[2] = (code >> 8) & 0xff;
    response[3] = code & 0xff;
    hdump = hexdump( THIS_MODULE, response, 4 );
    logTraceEIBD( THIS_MODULE, msgEIBDResponse, clientid, hdump );
    free( hdump );
    (void) pth_write( eibdcon[clientid].socket, response, 4 );
}


/**
 * send data packet to client
 */
static void eibdSendPacket( int clientid, unsigned char *buf, int length )
{
    char        *hdump;
    
    if( clientid >= config.eibdclients ) {
        return;
    }
    
    if( pth_write( eibdcon[clientid].socket, buf, length ) != length ) {
        logError( THIS_MODULE, msgEIBDSendAborted, clientid, strerror( errno ));
        close( eibdcon[clientid].socket );
        if( eibdcon[clientid].threadid != 0 ) pth_abort( eibdcon[clientid].threadid );
        eibdClearConnection( clientid );
    }
    hdump = hexdump( THIS_MODULE, buf, length );
    logTraceEIBD( THIS_MODULE, msgSocketForward, clientid, hdump );
    free( hdump );
    eibdcon[clientid].statsPacketsSent++;
    statsTotalSent++;
}

/*
 * Shutdown handler
 * - close sockets
 * 
 * this is executed as thread main
 */
static void serverShutdown( void )
{
    int                             loop;

    callbacks[shutdownEIBnetServer].flag = 0;
    
    // kill threads so we don't initiate any new actions
    if( tid_forward != 0 ) pth_abort( tid_forward );    // !!! maybe should use pth_cancel and set cancellation points in forwarder
    if( tid_eibd != 0 ) pth_abort( tid_eibd );

    for( loop = 0; loop < config.eibdclients; loop++ ) {
        if( eibdcon[loop].socket != 0 ) {
            if( eibdcon[loop].threadid != 0 ) pth_abort( eibdcon[loop].threadid );
            close( eibdcon[loop].socket );
            eibdClearConnection( loop );
        }
    }

    if( eibd_server  != 0 ) close( eibd_server );

    logInfo( THIS_MODULE, msgShutdown );
}

/*
 * SocketServerStatus
 * 
 * Return current connection status:
 *      (length of structure)
 *      1: active EIBD, port, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue
 *         per connected eibd client:
 *              unique connection id, address, port, packets received/sent
 */
char *eibdServerStatus( void )
{
    EIBNETIP_QUEUE          *queue;
    struct sockaddr_in      peer_address;
    socklen_t               addrlen;
    char                    *status;
    uint8_t                 connectedClients;
    uint16_t                statsQueueWaiting;
    uint16_t                statsQueueTotal;
    uint16_t                loop;
    uint32_t                tmp32;
    uint16_t                tmp16;
    uint16_t                idx;
    char                    *hdump;
    
    statsQueueWaiting = 0;
    statsQueueTotal = 0;
    for( queue = eibQueueServer; queue != NULL; queue = queue->next ) {
        statsQueueTotal++;
        if( queue->pending_others & QUEUE_PENDING_EIBD ) {
            statsQueueWaiting++;
        }
    }
    connectedClients = 0;
    if( eibdcon != NULL ) {
        for( loop = 0; loop < config.eibdclients; loop++ ) {
            if( eibdcon[loop].socket != 0 ) {
                connectedClients++;
            }
        }
    }
    
#define STATUS_EIBD_VERSION     1
#define STATUS_EIBD_BASE_LENGTH   20
#define STATUS_EIBD_CLIENT_LENGTH 18
    tmp16 = STATUS_EIBD_BASE_LENGTH;
    status = allocMemory( THIS_MODULE, 2 + tmp16 + connectedClients * STATUS_EIBD_CLIENT_LENGTH );
    idx = 0;
    idx = AppendBytes( idx, status, sizeof( tmp16 ), tmp16 + connectedClients * STATUS_EIBD_CLIENT_LENGTH );   // used internally, indicates size of buffer
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( tmp16 ));
    idx = AppendBytes( idx, status, 1, STATUS_EIBD_VERSION );
    idx = AppendBytes( idx, status, 1, (config.servers & SERVER_EIBD) ? 1 : 0 );
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.eibd_port ));        
    idx = AppendBytes( idx, status, 1, config.eibdclients );
    idx = AppendBytes( idx, status, 1, connectedClients );
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalReceived ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalSent ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( statsQueueWaiting ));
    
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( connectedClients * STATUS_EIBD_CLIENT_LENGTH ));
    addrlen = sizeof( peer_address );
    if( eibdcon != NULL ) {
        for( loop = 0; loop < config.eibdclients; loop++ ) {
            if( eibdcon[loop].socket > 0 ) {
                idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibdcon[loop].connectionid ));
                if( getpeername( eibdcon[loop].socket, (struct sockaddr *)&peer_address, &addrlen ) != 0 ) {
                    tmp32 = 0;
                    tmp16 = 0;
                } else {
                    tmp32 = (u_long)(peer_address.sin_addr.s_addr);
                    tmp16 = peer_address.sin_port;
                }
                idx = AppendBytes( idx, status, sizeof( uint32_t ), tmp32 );
                idx = AppendBytes( idx, status, sizeof( uint16_t ), tmp16 );
                idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibdcon[loop].statsPacketsReceived ));
                idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibdcon[loop].statsPacketsSent ));
            }
        }
    }
    hdump = hexdump( THIS_MODULE, status +2, STATUS_EIBD_BASE_LENGTH + connectedClients * STATUS_EIBD_CLIENT_LENGTH );
    logDebug( THIS_MODULE, "EIBD Server status: %s", hdump );
    free( hdump );
    
    return( status );
}


/**
 * get rest of command
 **/
static void eibdFlushRest( int clientid, int length )
{
    unsigned char   buf[1024];
    
    if( clientid >= config.eibdclients ) {
        return;
    }
    
    while( length > 0 ) {
        if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, buf, length, 1024, EIBD_REQ_TIMEOUT ) != 0 ) {
            eibdTerminateConnection( clientid );        // never returns
        }
        length -= 1024;
    }
}


static int eibdCheckConnectionType( int clientid, int type )
{
    if( clientid >= config.eibdclients ) {
        return( -1 );
    }
    
    return( (eibdcon[clientid].type == type) ? 0 : -1 );
}


/*
 * EIBDHandler thread
 * 
 * spawned for each socket connection
 * endless loop
 *   receive command
 *   if connection was closed: exit thread
 *   handle command
 * 
 * protocol:
 *   length             16 bit
 *   command            16 bit
 *   parameters
 *      knx address     16 bit
 *      write-only flag 1 byte
 * 
 * supported commands & parameters & data commands
 *   EIB_OPEN_GROUPCON              yes (flag)              EIB_GROUP_PACKET
 *   EIB_OPEN_T_GROUP               yes (address, flag)     EIB_APDU_PACKET
 *   EIB_OPEN_T_BROADCAST           yes (flag)              EIB_APDU_PACKET
 *   EIB_OPEN_VBUSMONITOR           no                      EIB_BUSMONITOR_PACKET   (receive only)
 * 
 * not supported
 *   EIB_OPEN_T_CONNECTION          yes         EIB_APDU_PACKET
 *   EIB_OPEN_T_INDIVIDUAL          yes         EIB_APDU_PACKET
 *   EIB_OPEN_T_TPDU                yes         EIB_APDU_PACKET
 *   EIB_OPEN_BUSMONITOR            no          EIB_BUSMONITOR_PACKET   (receive only)
 *   EIB_OPEN_BUSMONITOR_TEXT       no          EIB_BUSMONITOR_PACKET   (receive only)
 *   EIB_OPEN_VBUSMONITOR_TEXT      no          EIB_BUSMONITOR_PACKET   (receive only)
 *   EIB_M_INDIVIDUAL_ADDRESS_READ
 *   EIB_PROG_MODE
 *   EIB_MASK_VERSION
 *   EIB_M_INDIVIDUAL_ADDRESS_WRITE
 *   EIB_MC_CONNECTION
 *   EIB_LOAD_IMAGE
 *   EIB_CACHE_ENABLE
 *   EIB_CACHE_DISABLE
 *   EIB_CACHE_CLEAR
 *   EIB_CACHE_REMOVE
 *   EIB_CACHE_READ
 *   EIB_CACHE_READ_NOWAIT
 */
void *EIBDHandler( void *arg )
{
    CEMIFRAME           *cemiframe;
    EIBD_CMD_HEAD       req_header;
    EIBD_CMD_PARAM      req_param;
    uint16_t            cmd;
    sThreadArgs         *p_arg;
    sigset_t            signal_set;
    struct sockaddr_in  clientaddr;
    int                 sock;
    int                 rule;
    char                *hdump;
    char                ip_text[BUFSIZE_IPADDR];
    unsigned char       *buf;
    uint16_t            dst_addr;
    uint16_t            len;
    uint16_t            maxlen = 1;     // this value is wrong but required to keep the compiler happy
    int                 auth;
    int                 clientid;
    int                 start_idx;
    int                 result;
    
    logDebug( THIS_MODULE, "EIBDHandler() started" );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    // get our socket
    p_arg = (sThreadArgs *)arg;
    sock = p_arg->sock;
    auth = p_arg->auth;
    rule = p_arg->rule;
    memcpy( &clientaddr, &p_arg->client, sizeof( struct sockaddr_in ));
    free( arg );
    
    // get first free slot in eibd client table
    for( clientid = 0; clientid < config.eibdclients; clientid++ ) {
        if( eibdcon[clientid].socket == 0 ) {
            break;
        }
    }
    if( clientid >= config.eibdclients ) {
        // no more slots available
        logError( THIS_MODULE, msgEIBDNoneAvailable );
        eibdSendResponse( clientid, EIB_CLOSED );
        close( sock );
        pth_exit( NULL );               // does not return
    }
    
    // setup connection
    eibdcon[clientid].connectionid         = getConnectionId( THIS_MODULE, eibdGetUsedIds );
    eibdcon[clientid].socket               = sock;
    eibdcon[clientid].status               = E_NO_ERROR;
    eibdcon[clientid].type                 = EIBD_VIRGIN_CONNECTION;
    eibdcon[clientid].response_outstanding = 0;
    eibdcon[clientid].threadid             = pth_self();
    logVerbose( THIS_MODULE, msgSocketEstablished, clientid );
    
    // wait for requests and handle them
    while( true ) {
        // get header of next request
        if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &req_header, sizeof( req_header ), sizeof( req_header ), 0 ) != 0 ) {
            eibdTerminateConnection( clientid );        // never returns
        }
        hdump = hexdump( THIS_MODULE, &req_header, sizeof( req_header ));
        logTraceEIBD( THIS_MODULE, msgEIBDRequestHeader, clientid, hdump, eibdGetCommandName( ntohs( req_header.command )));
        free( hdump );
        result = E_NO_ERROR;
        buf = NULL;
        statsTotalReceived++;
        eibdcon[clientid].statsPacketsReceived++;
        
        /*
         * handle command
         */
        cmd = ntohs( req_header.command );
        req_header.size = ntohs( req_header.size ) -2;
        if( cmd == EIB_RESET_CONNECTION ) {
            eibdFlushRest( clientid, req_header.size -2 );
            eibdSendResponse( clientid, cmd );
            eibdcon[clientid].type = EIBD_VIRGIN_CONNECTION;
            logVerbose( THIS_MODULE, msgEIBDReset, clientid );
        } else if( eibdCheckConnectionType( clientid, EIBD_VIRGIN_CONNECTION ) == 0 ) {
            switch( cmd ) {
                case EIB_OPEN_GROUPCON:
                    if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &req_param, sizeof( req_param ), sizeof( req_param ), EIBD_REQ_TIMEOUT ) != 0 ) {
                        eibdTerminateConnection( clientid );        // never returns
                    }
                    eibdcon[clientid].writeonly = (req_param.writeonly == 0) ? 0 : 1;
                    logVerbose( THIS_MODULE, msgEIBDConGroupMon, clientid, (req_param.writeonly == 0) ? "RW" : "W" );
                    break;
                case EIB_OPEN_T_GROUP:
                    if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &req_param, sizeof( req_param ), sizeof( req_param ), EIBD_REQ_TIMEOUT ) != 0 ) {
                        eibdTerminateConnection( clientid );        // never returns
                    }
                    eibdcon[clientid].writeonly = (req_param.writeonly == 0) ? 0 : 1;
                    eibdcon[clientid].knxaddress = req_param.knxaddress;
                    hdump = knx_group( THIS_MODULE, eibdcon[clientid].knxaddress );
                    logVerbose( THIS_MODULE, msgEIBDConGroup, clientid, hdump, (req_param.writeonly == 0) ? "RW" : "W" );
                    free( hdump );
                    break;
                case EIB_OPEN_T_BROADCAST:
                    if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &req_param, sizeof( req_param ), sizeof( req_param ), EIBD_REQ_TIMEOUT ) != 0 ) {
                        eibdTerminateConnection( clientid );        // never returns
                    }
                    eibdcon[clientid].writeonly = (req_param.writeonly == 0) ? 0 : 1;
                    eibdcon[clientid].knxaddress = 0;
                    logVerbose( THIS_MODULE, msgEIBDConBroadcast, clientid, (req_param.writeonly == 0) ? "RW" : "W" );
                    break;
                case EIB_OPEN_VBUSMONITOR:
                    eibdcon[clientid].writeonly = 0;
                    eibdcon[clientid].knxaddress = 0;
                    logVerbose( THIS_MODULE, msgEIBDConMonitor, clientid, "vbusmonitor" );
                    break;
                case EIB_OPEN_BUSMONITOR:
                case EIB_OPEN_BUSMONITOR_TEXT:
                case EIB_OPEN_VBUSMONITOR_TEXT:
                    eibdFlushRest( clientid, req_header.size -2 );
                    eibdcon[clientid].writeonly = 0;
                    logVerbose( THIS_MODULE, msgEIBDNotImplemented, clientid, cmd );
                    cmd = EIB_PROCESSING_ERROR;
                    break;
                case EIB_M_INDIVIDUAL_ADDRESS_READ:
                case EIB_PROG_MODE:
                case EIB_MASK_VERSION:
                case EIB_M_INDIVIDUAL_ADDRESS_WRITE:
                case EIB_MC_CONNECTION:
                case EIB_LOAD_IMAGE:
                case EIB_CACHE_ENABLE:
                case EIB_CACHE_DISABLE:
                case EIB_CACHE_CLEAR:
                case EIB_CACHE_REMOVE:
                case EIB_CACHE_READ:
                case EIB_CACHE_READ_NOWAIT:
                    eibdFlushRest( clientid, req_header.size -2 );
                    logVerbose( THIS_MODULE, msgEIBDNotImplemented, clientid, cmd );
                    cmd = EIB_PROCESSING_ERROR;
                    break;
                default:
                    logError( THIS_MODULE, msgEIBDBadCommand, clientid, cmd );
                    eibdFlushRest( clientid, req_header.size -2 );
                    cmd = EIB_INVALID_REQUEST;
                    break;
            }
            eibdSendResponse( clientid, cmd );
            if( cmd != EIB_INVALID_REQUEST && cmd != EIB_PROCESSING_ERROR ) {
                eibdcon[clientid].type = cmd;
            }
        } else {
            buf = allocMemory( THIS_MODULE, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            memset( buf, '\0', sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            cemiframe = (CEMIFRAME *) &buf[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];
            start_idx = sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + 9;       // start of apci in cemiframe
            maxlen = sizeof( CEMIFRAME ) + 6 - 10;
            len = req_header.size;
            if( cmd == EIB_GROUP_PACKET && eibdCheckConnectionType( clientid, EIB_OPEN_GROUPCON ) == 0 ) {
                if( len < sizeof( dst_addr ) +1 ) {
                    start_idx = -1;
                } else {
                    if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &dst_addr, sizeof( dst_addr ), sizeof( dst_addr ), EIBD_REQ_TIMEOUT ) != 0 ) {
                        eibdTerminateConnection( clientid );        // never returns
                    }
                    len -= sizeof( dst_addr );
                    // cemiframe->tpci = T_GROUPDATA_REQ | (A_WRITE_VALUE_REQ & 0x03);
                }
            } else if( cmd == EIB_APDU_PACKET ) {
                if( eibdCheckConnectionType( clientid, EIB_OPEN_T_GROUP ) == 0 ) {
                    dst_addr = req_param.knxaddress;
                } else if( eibdCheckConnectionType( clientid, EIB_OPEN_T_BROADCAST ) == 0 ) {
                    dst_addr = 0;
                } else {
                    start_idx = -1;
                }
            } else {
                start_idx = -1;
            }
            if( start_idx == -1 ) {
                eibdFlushRest( clientid, req_header.size -2 );
                free( buf );
                logError( THIS_MODULE, msgEIBDBadCommand, clientid, eibdGetCommandName( cmd ), cmd );
                // eibdSendResponse( clientid, EIB_RESET_CONNECTION );
            } else {
                // create eibnet/ip tunneling request
                // format of request: eibnetip header, connection header, cemi frame, data
                // eibnetip header and connection header will be filled in by forwarder thread, just leave enough room
                // memory will be freed by eibnet/ip client when it releases the queued entry
                if( readFromSocket( THIS_MODULE, eibdcon[clientid].socket, clientid, &buf[start_idx], len, maxlen, EIBD_REQ_TIMEOUT ) != 0 ) {
                    eibdTerminateConnection( clientid );        // never returns
                }
                // create eib frame
                cemiframe->code   = L_DATA_REQ;
                cemiframe->zero   = 0;
                cemiframe->ctrl   = EIB_CTRL_DATA | EIB_CTRL_LENGTHBYTE | EIB_CTRL_NOREPEAT | EIB_CTRL_NONACK | EIB_CTRL_PRIO_LOW;
                cemiframe->ntwrk  = EIB_DAF_GROUP | EIB_NETWORK_HOPCOUNT;
                cemiframe->saddr  = /* htons( eibcon[0].knxaddress ) */ 0;
                cemiframe->daddr  = dst_addr;
                cemiframe->length = len -1;
                
                if( auth == secAddrTypeAllow ||
                    (cemiframe->ntwrk & EIB_DAF_GROUP &&
                        ((auth == secAddrTypeRead && (cemiframe->apci & 0x0080) == 0) ||
                         (auth == secAddrTypeWrite))) ) {
/*
                    if( cmd == EIB_GROUP_PACKET ) {
                        cemiframe->apci  &= 0x3f;         // keep data but clear out command fields
                        if( len == 1 ) {
                            // cemiframe->apci |= (A_WRITE_VALUE_REQ & 0xc0);
                        } else {
                            cemiframe->apci  = (A_WRITE_VALUE_REQ & 0xff);
                        }
                    }
*/
                    hdump = hexdump( THIS_MODULE, cemiframe, sizeof( CEMIFRAME ) -17 + cemiframe->length );
                    logDebug( THIS_MODULE, "Connection %d: Cemi frame: %s", clientid, hdump );
                    free( hdump );
                    // and finally, forward it
                    logDebug( THIS_MODULE, "Add tunneling request to client queue" );
                    addRequestToQueue( THIS_MODULE, &eibQueueClient, buf, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) -17 + cemiframe->length );
                    pth_cond_notify( &condQueueClient, TRUE );
                    
                } else {
                    logVerbose( THIS_MODULE, msgSecurityBlock, ip_addr( clientaddr.sin_addr.s_addr, ip_text ), ntohs( clientaddr.sin_port ), rule );
                }
            }
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * eibdFromBusForward thread
 * 
 * our eibnet/ip client puts tunneling requests it receives from the remote server on our queue
 * this thread forwards them to all the connected clients
 *   wait for request to be put on queue
 *   for a new request, send it to all connected clients
 */
void *eibdFromBusForward( void *arg )
{
    CEMIFRAME               *cemiframe;
    EIBNETIP_QUEUE          *queue;
    EIBD_RESP_APDU          resp_apdu;
    EIBD_RESP_GROUP         resp_group;
    EIBD_RESP_BUSMON_SMALL  resp_busmon_small;
    EIBD_RESP_BUSMON_LARGE  resp_busmon_large;
    pth_event_t             ev_wakeup;
    sigset_t                signal_set;
    uint8_t                 loop;
    time_t                  secs;
    int                     data_length;

    logDebug( THIS_MODULE, "Forwarder thread started" );

    // check if we have been started more than once
    pth_mutex_acquire( &mtxEIBDForwarder, FALSE, NULL );
    if( tid_forward != 0 ) {
        logWarning( THIS_MODULE, msgEIBDThreadTwice );
    }
    tid_forward = pth_self();
    pth_mutex_release( &mtxEIBDForwarder );
    
    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    secs = time( NULL ) +1;
    pth_mutex_init( &mtxQueueEIBD );
    pth_cond_init( &condQueueEIBD );
    
    while( true ) {
        // wait for request to be put on queue
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
        
        /*
         * mutex and cond is shared between eibnet/ip and eibd socket servers
         * as they use the same queue
         */
        pth_mutex_acquire( &mtxQueueServer, FALSE, NULL );
        pth_cond_await( &condQueueServer, &mtxQueueServer, ev_wakeup );
        pth_mutex_release( &mtxQueueServer );
        if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
            // logDebug( THIS_MODULE, "New entry on forwarder queue" );
        }
        pth_event_free( ev_wakeup, PTH_FREE_ALL );
        
        // handle all pending requests
        for( queue = eibQueueServer; queue != NULL;  ) {
            logDebug( THIS_MODULE, "Queue entry %d @ %08x, pending eibnet = %02x, others = %02x", queue->nr, queue, queue->pending_eibnet, queue->pending_others );
            if( queue->pending_others & QUEUE_PENDING_EIBD ) {
                cemiframe = (CEMIFRAME *) &(queue->data[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )]);
                if( (cemiframe->ntwrk & EIB_DAF_GROUP) != 0 && cemiframe->code == L_DATA_IND ) {
                    // data packet addressed to logical group
                    // our eibd-compatible server does not support requests addressed to physical devices
                    
                    // prepare data structure to send to clients
                    data_length = queue->len - (sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) +9);
                    
                    // apdu
                    resp_apdu.size = htons( 4 + data_length );
                    resp_apdu.command = htons( EIB_APDU_PACKET );
                    resp_apdu.source = cemiframe->saddr;
                    memcpy( &resp_apdu.data, &cemiframe->tpci, data_length );
                    
                    // group
                    resp_group.size = htons( 6 + data_length );
                    resp_group.command = htons( EIB_GROUP_PACKET );
                    resp_group.source = cemiframe->saddr;
                    resp_group.destination = cemiframe->daddr;
                    memcpy( &resp_group.data, &cemiframe->tpci, data_length );
                    
                    // busmonitor
                    if( cemiframe->length <= 15 ) {
                        resp_busmon_small.size = htons( 2 + 6 + cemiframe->length +2 );
                        resp_busmon_small.command = htons( EIB_BUSMONITOR_PACKET );
                        resp_busmon_small.control = 0x90 | (cemiframe->ctrl & 0x2c);
                        resp_busmon_small.source = cemiframe->saddr;
                        resp_busmon_small.dest = cemiframe->daddr;
                        resp_busmon_small.network = (cemiframe->ntwrk & 0xf0) | (cemiframe->length & 0x0f);
                        memcpy( &resp_busmon_small.data, &cemiframe->tpci, cemiframe->length +2 );
                    } else {
                        resp_busmon_large.size = htons( 2 + 7 + cemiframe->length +2 );
                        resp_busmon_large.command = htons( EIB_BUSMONITOR_PACKET );
                        resp_busmon_large.control = 0x10 | (cemiframe->ctrl & 0x2c);
                        resp_busmon_large.source = cemiframe->saddr;
                        resp_busmon_large.dest = cemiframe->daddr;
                        resp_busmon_large.network = (cemiframe->ntwrk & 0xf0);
                        resp_busmon_large.length = cemiframe->length;
                    }
                    
                    // send request to all active, read-write connections
                    for( loop = 0; loop < config.eibdclients; loop++ ) {
                        if( eibdcon[loop].socket != 0 && eibdcon[loop].writeonly == 0 ) {
                            /*
                             *  forward if:
                             *      broadcast connection    - all requests addressed to logical group 0 (group broadcast)
                             *      group connection        - all requests addressed to specific logical group (knxaddress)
                             *      group monitor           - all requests addressed to any logical group
                             *      bus monitor             - $$$
                             * 
                             * format:
                             *      code                        16 bit
                             *      source knx address          16 bit
                             *      destination knx address     16 bit, only for group monitor
                             *      data                        x bytes, tpdu (cemi tpci-data)
                             */
                            if( (eibdcon[loop].type == EIB_OPEN_T_BROADCAST && cemiframe->daddr == 0) ||
                                (eibdcon[loop].type == EIB_OPEN_T_GROUP && eibdcon[loop].knxaddress == cemiframe->daddr) ) {
                                eibdSendPacket( loop, (unsigned char *)&resp_apdu, ntohs( resp_apdu.size ) +2 );
                            } else if( eibdcon[loop].type == EIB_OPEN_GROUPCON ) {
                                eibdSendPacket( loop, (unsigned char *)&resp_group, ntohs( resp_group.size ) +2 );
                            } else if( eibdcon[loop].type == EIB_OPEN_VBUSMONITOR ) {
                                if( cemiframe->length <= 15 ) {
                                    eibdSendPacket( loop, (unsigned char *)&resp_busmon_small, ntohs( resp_busmon_small.size ) +2 );
                                } else {
                                    eibdSendPacket( loop, (unsigned char *)&resp_busmon_large, 2 + sizeof( resp_busmon_large ) );
                                    eibdSendPacket( loop, (unsigned char *)&cemiframe->apci, cemiframe->length +2 );
                                }
                            }
                            pth_yield( NULL );
                        }
                    }
                } else {
                    logDebug( THIS_MODULE, "Not a data packet addressed to a logical group" );
                }
            }
            
            // mark eibd client connections as done
            queue->pending_others &= ~QUEUE_PENDING_EIBD;

            // remove request from queue
            if( queue->pending_others == 0 && queue->pending_eibnet == 0 ) {
                eibQueueServer = removeRequestFromQueue( THIS_MODULE, eibQueueServer );                // assumes that only first queue entry can ever be removed
                queue = eibQueueServer;
            } else {
                logDebug( THIS_MODULE, "Go to next queue entry: current=%08x, next=%08x", queue, queue->next );
                queue = queue->next;
            }
        }
        
        // wake up every 36 seconds
        secs = time( NULL ) + 36;
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * EIBDListener thread
 * 
 * wait for connection requests by special eibd clients
 * spawn new thread for each client
 */
void *EIBDListener( void *arg )
{
    sThreadArgs             *threadargs;
    struct sockaddr_in      server, client;
    struct protoent         *proto_entry;
    pth_attr_t              thread_attr = pth_attr_new();
    sigset_t                signal_set;
    int                     eibd_con;
    int                     addr_len;
    int                     tmp;
    char                    ip_text[BUFSIZE_IPADDR];
    sSecurityAddr           *p_secAddr;
    eSecAddrType            secType;
    
    logInfo( THIS_MODULE, msgStartupEIBDServer );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    /*
     * initialize eibdcon table
     */
    eibdcon = allocMemory( THIS_MODULE, config.eibdclients * sizeof( EIBD_INFO ));
    for( tmp = 0; tmp < config.eibdclients; tmp++ ) {
        eibdClearConnection( tmp );
    }
    
    /*
     * register shutdown callback handler to clean up
     */
    tid_eibd = pth_self();
    callbacks[shutdownEIBDServer].func = serverShutdown;
    callbacks[shutdownEIBDServer].flag = 1;
    
    /*
     * start forwarder thread
     */
    if( tid_forward == 0 ) {
        pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBDFromBusForward" );
        if( pth_spawn( thread_attr, eibdFromBusForward, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread );
            Shutdown();
        }
    }
            
    /*
     * setup listener
     */
    proto_entry = getprotobyname( "tcp" );
    eibd_server = socket( PF_INET, SOCK_STREAM, proto_entry->p_proto );
    tmp = 1;
    setsockopt( eibd_server, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof( tmp ));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = config.eibd_ip;
    server.sin_port = htons( config.eibd_port );
    bind( eibd_server, (struct sockaddr *)&server, sizeof(struct sockaddr_in) );
            
    if( listen( eibd_server, SOMAXCONN ) != 0 ) {
        logCritical( THIS_MODULE, msgTCPNoListener, strerror( errno ));
        serverShutdown();
    }

    /*
     * Now loop endlessly for connections.
     */
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBDListener" );
    while( true ) {
        /*
         * receive connection
         */
        addr_len = sizeof( client );
        if( ( eibd_con = pth_accept( eibd_server, (struct sockaddr *)&client, (socklen_t *)&addr_len )) == -1 ) {
            logError( THIS_MODULE, msgTCPConnection, strerror( errno ));
            continue;
        }
        logVerbose( THIS_MODULE, msgSocketConnection, ip_addr( (uint32_t)client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ));
        
        /*
         * security check
         */
        if( config.secEIBD != NULL ) {
            for( p_secAddr = config.secEIBD; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
                if( (client.sin_addr.s_addr & p_secAddr->mask) == p_secAddr->address ) {
                    // matching rule found
                    break;
                }
            }
            if( p_secAddr != NULL ) {
                // what does rule prescribe?
                if( p_secAddr->type == secAddrTypeDeny ) {
                    // blocked address - skip request
                    logVerbose( THIS_MODULE, msgSecurityBlock, ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), p_secAddr->rule );
                    close( eibd_con );
                    continue;
                } else {
                    logDebug( THIS_MODULE, "Request from %s:%d allowed due to rule %d", ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), p_secAddr->rule );
                }
            }
        } else {
            p_secAddr = NULL;
        }
        
        // start handler thread
        secType = (p_secAddr != NULL) ? p_secAddr->type : config.defaultAuthEIBD;
        if( secType > config.maxAuthEIBD ) {
            secType = config.maxAuthEIBD;
        }
        logDebug( THIS_MODULE, "max auth=%d (config max=%d, config default=%d)", secType, config.maxAuthEIBD, config.defaultAuthEIBD );
        threadargs = allocMemory( THIS_MODULE, sizeof( sThreadArgs ));     // will be freed in EIBDHandler()
        threadargs->sock = eibd_con;
        threadargs->auth = secType;
        memcpy( &threadargs->client, &client, sizeof( struct sockaddr_in ));
        threadargs->rule = (p_secAddr != NULL) ? p_secAddr->rule : -1;
        if( pth_spawn( thread_attr, EIBDHandler, (void *)threadargs ) == NULL ) {
            logError( THIS_MODULE, msgInitThread );
            close( eibd_con );
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}
