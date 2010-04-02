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
 *   SocketTCP          receive connection requests from tcp/ip socket clients
 *   SocketUnix         receive connection requests from unix socket clients
 *   SocketHandler      spawned for each connection established by SocketServer which sends requests to bus
 *   SocketFromBus      one thread forwarding group address requests to appropriate clients
 * 
 * protocol
 *   key exchange       K                       request key exchange using Diffie-Hellman-Merkle algorithm
 *   diffie-hellman     Dparam                  receive clients DHM public value (Yc)
 *   authenticate       Auser password          authentication
 *   name               aidentifier             set value as the client identifier (usually used as type of client)
 *   version            V                       get API version
 *   read               Raddress                value is read from knx group address and returned
 *   read once          raddress                value is read from knx group address and returned, close connection after returning result
 *   write              Waddress length value   value is sent to knx group address
 *   write once         waddress length value   value is sent to knx group address, close connection after sending
 *   monitor            Maddress-mask           all requests addressed to masked knx group address are forwarded
 *   acknowledgement    x0                      response packet where x = A | D | a | W | X
 *   response           Klength params          send servers DHM parameters (P,G,Ys) to client
 *   response           Vversion                response packet for version
 *   response           xlength value           response packet where x = R | M
 *   error              Ecode                   error response packet
 * 
 *   the following are for management purposes
 *   connect            C1                      connect eibnet/ip client to remote server
 *   disconnect         C0                      disconnect eibnet/ip client from remote server
 *   get log level      l                       get current logging level
 *   log level          Llevel                  set new logging level
 *   status             S                       get status
 *   get access block   b                       get current access block level
 *   block accesses     Blevel                  block accesses above this level (0-3)
 *   status report      Slength status          current status of eibnetmux
 *   close connection   ccount id(s)            forcibly terminate connection(s)
 *   acknowledgement    x0                      confirm operation where x = B | C | D | L
 *   get access block   blevel                  retrieve current access block level
 *   error              Ecode                   error response packet
 * 
 *   parameters
 *     address                                  knx group address in network byte order
 *     address-mask                             mask of knx group address with allowable bits set, in network byte order
 *     length                                   number of bytes of value, in network byte order
 *     value                                    byte stream
 *     user                                     username as ASCII string
 *     password                                 user's password as ASCII string
 *     identifier                               connection identifier (ASCII string)
 *     params / param                           DHM parameters (P,G,Ys) for server, (Yc) for client
 *     version                                  API version id
 *     code                                     word containing error code, in network byte order
 * 
 *     level                                    new logging level (16 bit), in network byte order
 *                                              new access block level (16 bit), in network byte order
 *     count                                    number of connection ids
 *     id                                       connection id (32 bit)
 *     grace                                    0 = force disconnection, 1 = graceful, wait for clients
 *                                              to disconnect first (not implemented)
 *     status                                   common: version major, version minor, log level, uptime,
 *                                                      user id, group id, daemon mode
 *                                              eibnet/ip client: connection state, packets received/sent
 *                                                      length of sender queue, number of missed hearbeats
 *                                              eibnet/ip server: active, port, connected clients,
 *                                                      total packets received/sent, length of sender queue
 *                                              socket server: active, port, pipe name, max sockets, connected clients,
 *                                                      total commands received, length of sender queue
 *                                              per connected eibnet/ip client: address, port,
 *                                                      packets received/sent, length of sender queue
 *                                              per connected socket client: address, port,
 *                                                      packets received/sent, length of sender queue
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

#ifdef WITH_AUTHENTICATION
#include <polarssl/havege.h>
#include <polarssl/bignum.h>
#include <polarssl/dhm.h>
#include <polarssl/aes.h>
#include <polarssl/sha2.h>
#endif

#include "eibnetmux.h"
#include "include/log.h"
#include "include/socketserver_private.h"
#include "include/eibnetip_private.h"

#define  THIS_MODULE    logModuleSocketServer

/*
 * command verbs
 */
#ifdef WITH_AUTHENTICATION
#define COMMAND_VERBS   "KDAaVRrWwpMXClLbBcS"
#else
#define COMMAND_VERBS   "aVRrWwpMXClLbBcS"
#endif
#define COMMAND_VERBS_STANDARD      "RrWw"


/*
 * Globals
 */
SOCKET_INFO             *socketcon = NULL;              // saves all active connections
EIBNETIP_QUEUE          *eibQueueSocket = NULL;         // pointer to linked list of tunnel request packets
int                      sock_tcpserver = 0;            // tcp socket for communication with special tcp/ip clients
int                      sock_unixserver = 0;           // tcp socket for communication with special tcp/ip clients
pth_cond_t               condQueueSocket;               // signals tunneling forwarder on pending requests
pth_mutex_t              mtxSocketForwarder;            // make sure forwarder is only started once
#ifdef WITH_AUTHENTICATION
havege_state            *polarssl_hs = NULL;            // random number genereator for crypto functions
#endif


/*
 * Local variables
 */
static pth_t            tid_tcp = 0;
static pth_t            tid_unix = 0;
static pth_t            tid_frombus = 0;
static pth_mutex_t      mtxQueueSockets;
static uint8_t          socketTable_initialized = false;
static uint32_t         statsTotalSent = 0;                     // statistics
static uint32_t         statsTotalReceived = 0;


/*
 * Local types
 */
typedef struct _sThreadArgs {
    int     sock;
} sThreadArgs;


/*
 * local function declarations
 */
static void     socketClearConnection( uint8_t socketid );
static void     terminateConnection( int socketid );
static int      checkAuthorisation( int socketid, int requestedAuthorisation );
static int      returnResult( int socketid, uint8_t status, uint16_t code );
static void     serverShutdown( void );
static char     *SocketServerStatus( void );
// static int      socketGetUsedIds( uint8_t system, uint32_t **array, uint32_t threshold );


/*
 * socketClearConnection
 * 
 * reset socket information
 */
static void socketClearConnection( uint8_t socketid ) 
{
    if( socketid >= config.socketclients ) {
        return;
    }
    
    socketcon[socketid].connectionid         = 0;
    socketcon[socketid].socket               = 0;
    socketcon[socketid].type                 = 0;
    socketcon[socketid].status               = E_NO_ERROR;
    socketcon[socketid].response_outstanding = false;
    socketcon[socketid].threadid             = 0;
    socketcon[socketid].knxaddress           = 0;
    socketcon[socketid].statsPacketsSent     = 0;
    socketcon[socketid].statsPacketsReceived = 0;
    if( socketcon[socketid].name != NULL ) free( socketcon[socketid].name );
    if( socketcon[socketid].key  != NULL ) free( socketcon[socketid].key );
#ifdef WITH_AUTHENTICATION
    if( socketcon[socketid].p_dhm != NULL ) {
        dhm_free( socketcon[socketid].p_dhm );
        free( socketcon[socketid].p_dhm );
    }
    socketcon[socketid].p_dhm                = NULL;
#endif
    socketcon[socketid].name                 = NULL;
    socketcon[socketid].key                  = NULL;
    socketcon[socketid].user                 = NULL;
}


/*
 * Close socket connection with connection id
 */
static int socketCloseConnection( uint32_t connectionid )
{
    int     loop;
    
    for( loop = 0; loop < config.socketclients; loop++ ) {
        if( socketcon[loop].socket != 0 && socketcon[loop].connectionid == connectionid ) {
            logDebug( THIS_MODULE, "Found slot %d for connection id %d", loop, connectionid );
            if( socketcon[loop].threadid != 0 ) pth_abort( socketcon[loop].threadid );
            close( socketcon[loop].socket );
            socketClearConnection( loop );
            return( 0 );
        }
    }
    
    return( -1 );
}


/*
 * terminateConnection
 * 
 * closes socket connection and terminates handler thread
 */
static void terminateConnection( int socketid )
{
    if( socketid >= config.socketclients ) {
        return;
    }
    
    close( socketcon[socketid].socket );
    socketClearConnection( socketid );
    pth_exit( NULL );
}


/**
 * Return list of all allocated connection ids
 **/
int socketGetUsedIds( void *system, uint32_t **array, int entries, uint32_t threshold )
{
    int     loop;
    
    if( socketcon == NULL ) {
        return( 0 );
    }
    
    array = allocMemory( system, config.socketclients * sizeof( uint32_t ));
    for( loop = 0; loop < config.socketclients; loop++ ) {
        if( socketcon[loop].socket != 0 && socketcon[loop].connectionid > threshold ) {
            *array[entries++] = socketcon[loop].connectionid;
        }
    }
    return( entries );
}


/*
 * checkAuthorisation
 * 
 * checks if user is authorised for requested function
 */
static int checkAuthorisation( int socketid, int requestedAuthorisation )
{
    if( socketid < config.socketclients && socketcon[socketid].user != NULL ) {
        // check authorisation for logged in user
        return( socketcon[socketid].user->authorisation & requestedAuthorisation );
    }
    
    // check authorisation for anonymous user
    return( config.auth_anonymous & requestedAuthorisation );
}


/*
 * returnResult
 * 
 * send acknowledgement or error to socket client
 */
static int returnResult( int socketid, uint8_t status, uint16_t code )
{
    SOCKET_RSP_HEAD     rsp_header;
    int                 sock;
    char                *hdump;
    
    if( socketid >= config.socketclients ) {
        return( -1 );
    }
    
    sock = socketcon[socketid].socket;
    rsp_header.status = status;
    rsp_header.size   = htons( code );
    hdump = hexdump( THIS_MODULE, &rsp_header, sizeof( rsp_header ));
    if( status == SOCKET_STAT_ERROR ) {
        logTraceSocket( THIS_MODULE, msgSocketResult, socketid, "Error", hdump );
    } else {
        logTraceSocket( THIS_MODULE, msgSocketResult, socketid, "Acknowledgement", hdump );
    }
    free( hdump );
    // socketcon[socketid].statsPacketsSent++;         // should acknowledgements be counted ?
    if( pth_write( sock, &rsp_header, sizeof( rsp_header )) != sizeof( rsp_header )) {
        return( -1 );
    } else {
        return( 0 );
    }
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
    if( tid_frombus != 0 ) pth_abort( tid_frombus );    // !!! maybe should use pth_cancel and set cancellation points in forwarder
    if( tid_tcp != 0 ) pth_abort( tid_tcp );
    if( tid_unix != 0 ) pth_abort( tid_unix );

    for( loop = 0; loop < config.socketclients; loop++ ) {
        if( socketcon[loop].socket != 0 ) {
            if( socketcon[loop].threadid != 0 ) pth_abort( socketcon[loop].threadid );
            close( socketcon[loop].socket );
            socketClearConnection( loop );
        }
    }

    if( sock_tcpserver  != 0 ) close( sock_tcpserver );
    if( sock_unixserver != 0 ) {
        close( sock_unixserver );
        unlink( config.unix_path );
    }
    
#ifdef WITH_AUTHENTICATION
    if( polarssl_hs != NULL ) free( polarssl_hs );
#endif

    logInfo( THIS_MODULE, msgShutdown );
}

/*
 * SocketServerStatus
 * 
 * Return current connection status:
 *      (length of structure)
 *      1: active TCP, active named pipe, port, pipe name, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue
 *         per connected socket client:
 *              address, port, packets received/sent
 *      2: active TCP, active named pipe, port, pipe name, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue, client table length
 *         per connected socket client:
 *              address, port, packets received/sent, type identifier 
 *      3: active TCP, active named pipe, port, pipe name, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue, authentication support
 *         per connected socket client:
 *              address, port, packets received/sent, type identifier
 *      4: active TCP, active named pipe, port, pipe name, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue, authentication support
 *         per connected socket client:
 *              address, port, packets received/sent, type identifier, authenticated user
 *      5: active TCP, active named pipe, port, pipe name, max sockets, connected clients,
 *         total commands received, total packets forwarded, length of sender queue, authentication support
 *         per connected socket client:
 *              unique connection id, address, port, packets received/sent, type identifier, authenticated user
 */
static char *SocketServerStatus( void )
{
    EIBNETIP_QUEUE          *queue;
    struct sockaddr_in      peer_address;
    socklen_t               addrlen;
    char                    *status;
    uint8_t                 connectedClients;
    uint16_t                statsQueueWaiting;
    uint16_t                statsQueueTotal;
    uint16_t                loop;
    uint8_t                 namelength;
    uint32_t                tmp32;
    uint16_t                tmp16;
    uint16_t                idx;
    uint16_t                identifier_lengths;
    char                    *hdump;
    
    statsQueueWaiting = 0;
    statsQueueTotal = 0;
    for( queue = eibQueueServer; queue != NULL; queue = queue->next ) {
        statsQueueTotal++;
        if( queue->pending_others & QUEUE_PENDING_SOCKET ) {
            statsQueueWaiting++;
        }
    }
    connectedClients = 0;
    identifier_lengths = 0;
    for( loop = 0; loop < config.socketclients; loop++ ) {
        if( socketcon[loop].socket != 0 ) {
            connectedClients++;
            if( socketcon[loop].name != NULL ) {
                identifier_lengths += strlen( socketcon[loop].name );
            }
            if( socketcon[loop].user != NULL && socketcon[loop].user->name != NULL ) {
                identifier_lengths += strlen( socketcon[loop].user->name );
            }
        }
    }

#define STATUS_SOCKET_VERSION     5
#define STATUS_SOCKET_BASE_LENGTH   22
#define STATUS_SOCKET_CLIENT_LENGTH 22
    namelength = (config.unix_path != NULL) ? strlen( config.unix_path ) +1 : 1;
    tmp16 = STATUS_SOCKET_BASE_LENGTH + namelength;
    status = allocMemory( THIS_MODULE, 2 + tmp16 + connectedClients * STATUS_SOCKET_CLIENT_LENGTH + identifier_lengths );
    idx = 0;
    idx = AppendBytes( idx, status, sizeof( tmp16 ), tmp16 + connectedClients * STATUS_SOCKET_CLIENT_LENGTH + identifier_lengths );   // used internally, indicates size of buffer
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( tmp16 ));
    idx = AppendBytes( idx, status, 1, STATUS_SOCKET_VERSION );
    idx = AppendBytes( idx, status, 1, (config.servers & SERVER_TCP) ? 1 : 0 );
    idx = AppendBytes( idx, status, 1, (config.servers & SERVER_UNIX) ? 1 : 0 );
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.tcp_port ));        
    memcpy( &status[idx], (config.unix_path != NULL) ? config.unix_path : "\0", namelength );
    idx += namelength;
    idx = AppendBytes( idx, status, 1, config.socketclients );
    idx = AppendBytes( idx, status, 1, connectedClients );
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalReceived ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalSent ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( statsQueueWaiting ));
#ifdef WITH_AUTHENTICATION
    idx = AppendBytes( idx, status, 1, 1 );
#else
    idx = AppendBytes( idx, status, 1, 0 );
#endif
    
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( connectedClients * STATUS_SOCKET_CLIENT_LENGTH + identifier_lengths ));
    addrlen = sizeof( peer_address );
    for( loop = 0; loop < config.socketclients; loop++ ) {
        if( socketcon[loop].socket > 0 ) {
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( socketcon[loop].connectionid ));
            if( getpeername( socketcon[loop].socket, (struct sockaddr *)&peer_address, &addrlen ) != 0 ) {
                tmp32 = 0;
                tmp16 = 0;
            } else {
                tmp32 = (u_long)(peer_address.sin_addr.s_addr);
                tmp16 = peer_address.sin_port;
            }
            idx = AppendBytes( idx, status, sizeof( uint32_t ), tmp32 );
            idx = AppendBytes( idx, status, sizeof( uint16_t ), tmp16 );
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( socketcon[loop].statsPacketsReceived ));
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( socketcon[loop].statsPacketsSent ));
            if( socketcon[loop].name != NULL ) {
                idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( strlen( socketcon[loop].name )));
                memcpy( &status[idx], socketcon[loop].name, strlen( socketcon[loop].name ));
                idx += strlen( socketcon[loop].name );
            } else {
                idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( 0 ));
            }
            if( socketcon[loop].user != NULL && socketcon[loop].user->name != NULL ) {
                idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( strlen( socketcon[loop].user->name )));
                memcpy( &status[idx], socketcon[loop].user->name, strlen( socketcon[loop].user->name ));
                idx += strlen( socketcon[loop].user->name );
            } else {
                idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( 0 ));
            }
        }
    }
    hdump = hexdump( THIS_MODULE, status +2, STATUS_SOCKET_BASE_LENGTH + namelength + connectedClients * STATUS_SOCKET_CLIENT_LENGTH + identifier_lengths );
    logDebug( THIS_MODULE, "SocketServer status: %s", hdump );
    free( hdump );
    
    return( status );
}


/*
 * SocketHandler thread
 * 
 * spawned for each socket connection
 * endless loop
 *   receive request
 *   if connection was closed: exit thread
 *   if type = write: build & send CEMI write request, continue
 *   if type = read:  build & send CEMI read request, continue, response will be provided by SocketFromBusForward thread
 *   if type = monitor: setup socketcon information, exit thread, rest will be handled by SocketFromBusForward thread
 */
void *SocketHandler( void *arg )
{
    CEMIFRAME           *cemiframe;
    SOCKET_CMD_HEAD     req_header;
    SOCKET_RSP_HEAD     rsp_header;
    sPassthroughParams  passthrough;
    sThreadArgs         *p_arg;
    sigset_t            signal_set;
    int                 sock;
    unsigned char       *buf;
    uint16_t            len;
    uint16_t            maxlen = 1;     // this value is wrong but required to keep the compiler happy
    int                 socketid;
    int                 result;
    uint32_t            connid;
    char                *stat_common;
    char                *stat_eibclient;
    char                *stat_eibserver;
    char                *stat_socket;
    char                *stat_eibd;
    char                *hdump;
    char                *hdump2;
#ifdef WITH_AUTHENTICATION
    unsigned char       *password;
    unsigned char       password_hash[32];
    unsigned char       iv[16];
    int                 iv_off;
    int                 dhm_param_len;
    sSecurityUser       *p_secUser;
    aes_context         aes;
#endif                    
    
    logDebug( THIS_MODULE, "SocketHandler() started" );

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
    free( arg );
    
    // get first free slot in socket table
    logDebug( THIS_MODULE, "Checking for empty slot in %d connection entries", config.socketclients );
    for( socketid = 0; socketid < config.socketclients; socketid++ ) {
        if( socketcon[socketid].socket == 0 ) {
            break;
        }
        logDebug( THIS_MODULE, "Slot %d used (socket %d)", socketid, socketcon[socketid].socket );
    }
    if( socketid >= config.socketclients ) {
        // no more slots available
        logError( THIS_MODULE, msgSocketNoneAvailable );
        (void) returnResult( socketid, SOCKET_STAT_ERROR, E_NO_SOCKETS );
        close( sock );
        pth_exit( NULL );               // does not return
    }

    // setup connection
    socketcon[socketid].connectionid         = getConnectionId( THIS_MODULE, socketGetUsedIds );
    socketcon[socketid].socket               = sock;
    socketcon[socketid].status               = E_NO_ERROR;
    socketcon[socketid].response_outstanding = false;
    socketcon[socketid].threadid             = pth_self();
    socketcon[socketid].name                 = NULL;
    socketcon[socketid].key                  = NULL;
#ifdef WITH_AUTHENTICATION
    socketcon[socketid].p_dhm                = NULL;
#endif
    socketcon[socketid].user                 = NULL;
    logVerbose( THIS_MODULE, msgSocketEstablished, socketid );
    
    // wait for requests and handle them
    while( true ) {
        // get header of next request
        len = pth_read( sock, &req_header, sizeof( req_header ));

        if( len == 0 ) {
            // end of file means client closed connection - terminate
            logVerbose( THIS_MODULE, msgSocketConnectionClosed, socketid );
            result = E_SOCKET_CLOSED;
        } else {
            hdump = hexdump( THIS_MODULE, &req_header, len );
            logDebug( THIS_MODULE, "Connection %d: Received %d bytes: %s", socketid, len, hdump );
            free( hdump );
            if( len < sizeof( req_header )) {
                // invalid header means bad request - abort
                logVerbose( THIS_MODULE, msgSocketBadPacket, socketid );
                result = E_BAD_REQUEST;
            } else if( req_header.cmd == '\0' || strchr( COMMAND_VERBS, req_header.cmd ) == 0 ) {
                // invalid command
                logVerbose( THIS_MODULE, msgSocketBadCommand, socketid, req_header.cmd );
                result = E_CMD_UNKNOWN;
            } else {
                hdump = hexdump( THIS_MODULE, &req_header, len );
                logTraceSocket( THIS_MODULE, msgSocketRequestHeader, socketid, hdump );
                free( hdump );
                result = E_NO_ERROR;
                buf = NULL;
            }
        }
        statsTotalReceived++;
        if( result != E_NO_ERROR ) {
            (void) returnResult( socketid, SOCKET_STAT_ERROR, result );
            if( result != E_CMD_UNKNOWN ) {
                terminateConnection( socketid );      // does not return
            }
            continue;
        }
        socketcon[socketid].statsPacketsReceived++;
        if( req_header.cmd == SOCKET_CMD_EXIT ) {
            logVerbose( THIS_MODULE, msgSocketConnectionClosed, socketid );
            (void) returnResult( socketid, SOCKET_STAT_EXIT, 0 );
            terminateConnection( socketid );      // does not return
        }
        socketcon[socketid].type = req_header.cmd;
        
        /*
         * get API version number
         */
        if( req_header.cmd == SOCKET_CMD_VERSION ) {
            logVerbose( THIS_MODULE, msgSocketCommand, socketid, "version", req_header.cmd );
            if( returnResult( socketid, SOCKET_STAT_VERSION, SOCKET_API_VERSION ) != 0 ) {
                logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                terminateConnection( socketid );        // does not return
            }
            continue;
        }
        /*
         * set the client type identifier
         */
        if( req_header.cmd == SOCKET_CMD_NAME ) {
            logVerbose( THIS_MODULE, msgSocketCommand, socketid, "name", req_header.cmd );
            len = ntohs( req_header.address );
            logDebug( THIS_MODULE, "Connection %d: Name length=%d", socketid, len );
            socketcon[socketid].name = allocMemory( THIS_MODULE, min16( len +1, SOCKET_NAME_MAX_LENGTH +1 ));
            if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, socketcon[socketid].name, len, SOCKET_NAME_MAX_LENGTH, SOCKET_REQ_TIMEOUT ) != 0 ) {
                terminateConnection( socketid );        // never returns
            }
            socketcon[socketid].name[min16( len, SOCKET_NAME_MAX_LENGTH )] = '\0';
            logVerbose( THIS_MODULE, msgSocketIdentifier, socketid, socketcon[socketid].name );
            if( returnResult( socketid, SOCKET_STAT_NAME, 0 ) != 0 ) {
                logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                terminateConnection( socketid );        // does not return
            }
            continue;
        }
        
#ifdef WITH_AUTHENTICATION
        /*
         * authenticate user
         * 
         * format is:
         *      username \0 password \0
         */
        if( req_header.cmd == SOCKET_CMD_AUTH ) {
            logVerbose( THIS_MODULE, msgSocketCommand, socketid, "authenticate", req_header.cmd );
            len = ntohs( req_header.address );
            logDebug( THIS_MODULE, "Connection %d: Parameter length=%d", socketid, len );
            buf = allocMemory( THIS_MODULE, len +1 );
            if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, buf, len, len, SOCKET_REQ_TIMEOUT ) != 0 ) {
                terminateConnection( socketid );        // never returns
            }
            buf[len] = '\0';
            hdump = hexdump( THIS_MODULE, buf, len );
            logDebug( THIS_MODULE, "Connection %d: auth parameters: %s", socketid, hdump );
            free( hdump );
            // decrypt
            if( socketcon[socketid].key != NULL ) {
                // format: aes_ecb( iv ), aes_cfb( msg )
                hdump = hexdump( THIS_MODULE, socketcon[socketid].key, 256 / 8 );
                logDebug( THIS_MODULE, "Connection %d: key: %s", socketid, hdump );
                free( hdump );
                aes_setkey_dec( &aes, socketcon[socketid].key, 256 );
                aes_crypt_ecb( &aes, AES_DECRYPT, buf, iv );
                hdump = hexdump( THIS_MODULE, iv, 16 );
                logDebug( THIS_MODULE, "Connection %d: decrypted iv: %s", socketid, hdump );
                free( hdump );
                iv_off = 0;
                aes_setkey_enc( &aes, socketcon[socketid].key, 256 );
                aes_crypt_cfb128( &aes, AES_ENCRYPT, len -1, &iv_off, iv, buf + 16, buf );
                buf[len -16] = '\0';
                hdump = hexdump( THIS_MODULE, buf, len -16 );
                logDebug( THIS_MODULE, "Connection %d: decrypted parameters: %s", socketid, hdump );
                free( hdump );
            }
            // get user name
            len = strlen( (char *)buf );
            socketcon[socketid].name = allocMemory( THIS_MODULE, min16( len +1, SOCKET_NAME_MAX_LENGTH +1 ));
            memcpy( socketcon[socketid].name, buf, min16( len, SOCKET_NAME_MAX_LENGTH ));
            socketcon[socketid].name[min16( len, SOCKET_NAME_MAX_LENGTH )] = '\0';
            logVerbose( THIS_MODULE, msgSocketAuthenticate, socketid, socketcon[socketid].name );
            // get password
            password = &buf[len +1];
            // find user
            for( p_secUser = config.secUsers; p_secUser != NULL; p_secUser = p_secUser->next ) {
                if( strcmp( socketcon[socketid].name, p_secUser->name ) == 0 ) {
                    break;
                }
            }
            if( p_secUser != NULL ) {
                // hash password
                sha2( password, strlen( (char *)password ), password_hash, 0 );
                // compare hashes
                if( memcmp( p_secUser->hash, password_hash, 32 ) == 0 ) {
                    socketcon[socketid].user = p_secUser;
                    if( returnResult( socketid, SOCKET_STAT_AUTH, 0 ) != 0 ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        terminateConnection( socketid );        // does not return
                    }
                    continue;
                }
            }
            logVerbose( THIS_MODULE, msgSocketAuthNoUser, socketid, socketcon[socketid].name );
            if( returnResult( socketid, SOCKET_STAT_ERROR, E_PASSWORD ) != 0 ) {
                logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                terminateConnection( socketid );        // does not return
            }
            continue;
        }
        /*
         * initiate key exchange
         *      send our DHM parameters to client
         * 
         * later on, client will send its public value (command D)
         */
        if( req_header.cmd == SOCKET_CMD_KEY ) {
            logVerbose( THIS_MODULE, msgSocketCommand, socketid, "key exchange", req_header.cmd );
            if( config.dhm == NULL ) {
                logError( THIS_MODULE, msgSocketDHMinit, socketid );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_DHM ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
                continue;
            }
            // create DHM parameters
            if( socketcon[socketid].p_dhm == NULL ) {
                socketcon[socketid].p_dhm = allocMemory( THIS_MODULE, sizeof( dhm_context ));
                memset( socketcon[socketid].p_dhm, 0, sizeof( dhm_context ));
                logDebug( THIS_MODULE, "Connection %d: copying DHM prime to thread", socketid );
                result = mpi_copy( &(socketcon[socketid].p_dhm->P), &(config.dhm->P) );
                result |= mpi_copy( &(socketcon[socketid].p_dhm->G), &(config.dhm->G) );
                if( result != 0 ) {
                    logError( THIS_MODULE, msgSocketDHMFailure, socketid, result, "copy context" );
                    if( returnResult( socketid, SOCKET_STAT_ERROR, E_DHM ) != 0 ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        terminateConnection( socketid );        // does not return
                    }
                    continue;
                }
            }
            buf = allocMemory( THIS_MODULE, 1024 );
            memset( buf, '\0', 1024 );
            logDebug( THIS_MODULE, "Connection %d: create DHM parameters", socketid );
            result = dhm_make_params( socketcon[socketid].p_dhm, 256, buf, &dhm_param_len, havege_rand, polarssl_hs );
            if( result == 0 ) {
                // send to client
                len = dhm_param_len;
                logDebug( THIS_MODULE, "Connection %d: send DHM parameters to client", socketid );
                rsp_header.status = SOCKET_STAT_KEY;
                rsp_header.size = htons( len );
                if( pth_write( socketcon[socketid].socket, &rsp_header, sizeof( rsp_header )) != sizeof( rsp_header ) || 
                    pth_write( socketcon[socketid].socket, buf, len ) != len ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    free( buf );
                    terminateConnection( socketid );        // does not return
                }
            }
            free( buf );
            if( result != 0 ) {
                logError( THIS_MODULE, msgSocketDHMFailure, socketid, result, "make params" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_DHM ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
                continue;
            }
            continue;
        }
        /*
         * get client's public key
         *      and calculate the secret
         */
        if( req_header.cmd == SOCKET_CMD_DHM ) {
            logVerbose( THIS_MODULE, msgSocketCommand, socketid, "DHM client public value", req_header.cmd );
            len = ntohs( req_header.address );
            buf = allocMemory( THIS_MODULE, min16( len, socketcon[socketid].p_dhm->len ));
            if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, buf, len, socketcon[socketid].p_dhm->len, SOCKET_REQ_TIMEOUT ) != 0 ) {
                terminateConnection( socketid );        // never returns
            }
            if( socketcon[socketid].p_dhm == NULL ) {
                logError( THIS_MODULE, msgSocketDHMinit, socketid );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_DHM ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
                continue;
            }
            result = dhm_read_public( socketcon[socketid].p_dhm, buf, socketcon[socketid].p_dhm->len );
            free( buf );
            if( result == 0 ) {
                buf = allocMemory( THIS_MODULE, 512 );
                result = dhm_calc_secret( socketcon[socketid].p_dhm, buf, &dhm_param_len );
                if( socketcon[socketid].key != NULL ) free( socketcon[socketid].key );
                socketcon[socketid].key = allocMemory( THIS_MODULE, dhm_param_len );
                memcpy( socketcon[socketid].key, buf, dhm_param_len );
                free( buf );
            }
            if( result == 0 ) {
                if( returnResult( socketid, SOCKET_STAT_DHM, 0 ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            } else {
                logError( THIS_MODULE, msgSocketDHMFailure, socketid, result, "client key" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_DHM ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        }
#endif  /* WITH_AUTHENTICATION */
        
        /*
         * for monitoring connection, setup knx group address mask
         * forwarding will be handled by SocketFromBusForward()
         */
        if( req_header.cmd == SOCKET_CMD_MONITOR ) {
            if( checkAuthorisation( socketid, authMonitor )) {
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "monitor", ntohs( req_header.address ));
                socketcon[socketid].knxaddress = !req_header.address;
                // socketcon[socketid].threadid   = 0;
                // pth_exit( NULL );
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "monitor" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
                socketcon[socketid].type = 0;
            }
            continue;
        }
        
        /*
         * handle management requests
         */
        if( req_header.cmd == SOCKET_CMD_MGMT_CLIENT ) {
            if( checkAuthorisation( socketid, authMgmtClient )) {
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "client management", req_header.cmd );
                EIBnetClientSetState( ntohs( req_header.address ));
                if( returnResult( socketid, SOCKET_STAT_MGMT_CLIENT, 0 ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "client connection management" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_GETLOG ) {
            if( checkAuthorisation( socketid, authMgmtStatus )) {   // retrieving need status authorisation (as it is contained in status report, too
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "get log level", ntohs( req_header.address ));
                if( returnResult( socketid, SOCKET_STAT_MGMT_GETLOG, logGetLevel() ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "get log level" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_SETLOG ) {
            if( checkAuthorisation( socketid, authMgmtLog )) {
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "set log level", ntohs( req_header.address ));
                logSetLevel( ntohs( req_header.address ));
                if( returnResult( socketid, SOCKET_STAT_MGMT_SETLOG, 0 ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "set log level" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_GETBLOCK ) {
            if( checkAuthorisation( socketid, authMgmtStatus )) {   // retrieving need status authorisation (as it is contained in status report, too
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "get access block level", ntohs( req_header.address ));
                if( returnResult( socketid, SOCKET_STAT_MGMT_GETBLOCK, config.maxAuthEIBnet ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "get access block level" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_SETBLOCK ) {
            if( checkAuthorisation( socketid, authMgmtBlock )) {
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "set access block level", ntohs( req_header.address ));
                if( (unsigned int)ntohs( req_header.address ) < 4 ) {
                    config.maxAuthEIBnet = ntohs( req_header.address );
                    if( returnResult( socketid, SOCKET_STAT_MGMT_SETBLOCK, 0 ) != 0 ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        terminateConnection( socketid );        // does not return
                    }
                } else {
                    if( returnResult( socketid, SOCKET_STAT_ERROR, E_PARAMETER ) != 0 ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        terminateConnection( socketid );        // does not return
                    }
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "set access block level" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_CLOSE ) {
            if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, &connid, sizeof( connid ), sizeof( connid ), SOCKET_REQ_TIMEOUT ) != 0 ) {
                terminateConnection( socketid );        // never returns
            }
            if( checkAuthorisation( socketid, authMgmtConnection )) {
                req_header.address = ntohs( req_header.address );
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "force close connection", req_header.address );
                connid = ntohl( connid );
                logDebug( THIS_MODULE, "Connection %d: closed by admin", connid );
                result = E_NO_ERROR;
                if( req_header.address == 1 && connid <= EIBNETIP_MAXCONNECTIONS ) {
                    // close EIBnet/IP connection
                    if( eibNetCloseConnection( connid ) != 0 ) {
                        result = E_PARAMETER;
                    }
                } else if( req_header.address == 2 && connid < config.socketclients ) {
                    // close socket connection
                    if( socketCloseConnection( connid ) != 0 ) {
                        result = E_PARAMETER;
                    }
                } else {
                    result = E_PARAMETER;
                }
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "force close connection" );
                result = E_UNAUTHORISED;
            }
            if( result == E_NO_ERROR ) {
                result = returnResult( socketid, SOCKET_STAT_MGMT_CLOSE, result );
            } else {
                result = returnResult( socketid, SOCKET_STAT_ERROR, result );
            }
            if( result != 0 ) {
                logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                terminateConnection( socketid );        // does not return
            }
            continue;
        } else if( req_header.cmd == SOCKET_CMD_MGMT_STATUS ) {
            if( checkAuthorisation( socketid, authMgmtStatus )) {
                // get status information and build response packet
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "status", 0 );
                stat_common    = eibnetmuxStatus();
                stat_eibclient = EIBnetClientStatus();
                stat_eibserver = EIBnetServerStatus();
                stat_socket    = SocketServerStatus();
                stat_eibd      = eibdServerStatus();
                len = *((uint16_t *)stat_common) + *((uint16_t *)stat_eibclient) + *((uint16_t *)stat_eibserver) + *((uint16_t *)stat_socket) + *((uint16_t *)stat_eibd) + 5;
                rsp_header.status = SOCKET_STAT_MGMT_STATUS;
                rsp_header.size = htons( len );
                logDebug( THIS_MODULE, "Connection %d: Status will be %d bytes", socketid, len );
                buf = allocMemory( THIS_MODULE, len );
                /*
                 ************************************************************
                 * status structure version                                 *
                 * increment if you change the following few lines          *
                 *   1: common (main.c), eibnet/ip client (client.c),       *
                 *      eibnet/ip server (server.c),                        *
                 *      eibnetmux clients (socketserver.c)                  *
                 *   2: common (main.c), eibnet/ip client (client.c),       *
                 *      eibnet/ip server (server.c),                        *
                 *      eibnetmux clients (socketserver.c),                 *
                 *      eibd server (eibdserver.c)                          *
                 ************************************************************
                 */
                buf[0] = 2;     // version
                len = 1;
                memcpy( &buf[len], stat_common + 2, *((uint16_t *)stat_common ) );
                len += *((uint16_t *)stat_common);
                memcpy( &buf[len], stat_eibclient + 2, *((uint16_t *)stat_eibclient) );
                len += *((uint16_t *)stat_eibclient);
                memcpy( &buf[len], stat_eibserver + 2, *((uint16_t *)stat_eibserver) );
                len += *((uint16_t *)stat_eibserver);
                memcpy( &buf[len], stat_socket + 2, *((uint16_t *)stat_socket) );
                len += *((uint16_t *)stat_socket);
                memcpy( &buf[len], stat_eibd + 2, *((uint16_t *)stat_eibd) );
                
                hdump = hexdump( THIS_MODULE, buf, ntohs( rsp_header.size ));
                hdump2 = hexdump( THIS_MODULE, &rsp_header, sizeof( rsp_header ));
                logTraceSocket( THIS_MODULE, msgSocketStatusInfo, socketid, 
                                hdump2, hdump );
                free( hdump );
                free( hdump2 );
                socketcon[socketid].statsPacketsSent++;
                statsTotalSent++;
                len = ntohs( rsp_header.size );
                if( pth_write( socketcon[socketid].socket, &rsp_header, sizeof( rsp_header )) != sizeof( rsp_header ) || 
                    pth_write( socketcon[socketid].socket, buf, len ) != len ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        close( socketcon[socketid].socket );
                        if( socketcon[socketid].threadid != 0 ) pth_abort( socketcon[socketid].threadid );
                        socketClearConnection( socketid );
                }
                
                free( buf );
                free( stat_eibd );
                free( stat_socket );
                free( stat_eibserver );
                free( stat_eibclient );
                free( stat_common );
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "status" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
            }
            continue;
        }
        
        /*
         * from here on, operations send/receive data to/from bus
         */
        if( strchr( COMMAND_VERBS_STANDARD, req_header.cmd ) != 0 ) {
            /*
             * handle standard read/write operations
             */
            /*
             * get number of value bytes to add to CEMI request frame
             */
            switch( req_header.cmd ) {
                case SOCKET_CMD_WRITE:
                case SOCKET_CMD_WRITE_ONCE:
                    if( checkAuthorisation( socketid, authWrite )) {
                        logVerbose( THIS_MODULE, msgSocketCommand, socketid, "write", ntohs( req_header.address ));
                        if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, &len, sizeof( len ), 2, SOCKET_REQ_TIMEOUT ) != 0 ) {
                            terminateConnection( socketid );        // never returns
                        }
                        len = ntohs( len );
                        maxlen = sizeof( CEMIFRAME ) + 6 - 10;
                        logDebug( THIS_MODULE, "Connection %d: Length=%d", socketid, len );
                    } else {
                        logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "write" );
                        if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                            logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                            terminateConnection( socketid );        // does not return
                        }
                        socketcon[socketid].type = 0;
                        continue;
                    }
                    break;
                case SOCKET_CMD_READ:
                case SOCKET_CMD_READ_ONCE:
                    if( checkAuthorisation( socketid, authRead )) {
                        logVerbose( THIS_MODULE, msgSocketCommand, socketid, "read", ntohs( req_header.address ));
                        len = 0;
                        socketcon[socketid].knxaddress = req_header.address;
                    } else {
                        logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "read" );
                        if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                            logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                            terminateConnection( socketid );        // does not return
                        }
                        socketcon[socketid].type = 0;
                        continue;
                    }
                    break;
            }
    
            // create eibnet/ip tunneling request
            // put it on our client's forwarder queue
            // format of request: eibnetip header, connection header, cemi frame, data
            // eibnetip header and connection header will be filled in by forwarder thread, just leave enough room
            // memory will be freed by eibnet/ip client when it releases the queued entry
            buf = allocMemory( THIS_MODULE, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            memset( buf, '\0', sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            if( req_header.cmd == SOCKET_CMD_WRITE || req_header.cmd == SOCKET_CMD_WRITE_ONCE ) {
                if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, &buf[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + 10] /* start of apci in cemiframe */, len, maxlen, SOCKET_REQ_TIMEOUT ) != 0 ) {
                    terminateConnection( socketid );        // never returns
                }
            }
            // len++;          // include checksum
            
            // create eib frame
            cemiframe = (CEMIFRAME *) &buf[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];
            cemiframe->code   = L_DATA_REQ;
            cemiframe->zero   = 0;
            cemiframe->ctrl   = EIB_CTRL_DATA | EIB_CTRL_LENGTHBYTE | EIB_CTRL_NOREPEAT | EIB_CTRL_NONACK | EIB_CTRL_PRIO_LOW;
            cemiframe->ntwrk  = EIB_DAF_GROUP | EIB_NETWORK_HOPCOUNT;
            cemiframe->saddr  = /* htons( eibcon[0].knxaddress ) */ 0;
            cemiframe->tpci   = T_GROUPDATA_REQ;
            cemiframe->apci  &= 0x3f;         // keep data but clear out command fields
            cemiframe->daddr  = req_header.address;
            switch( req_header.cmd ) {
                case SOCKET_CMD_READ:
                case SOCKET_CMD_READ_ONCE:
                    cemiframe->length = 1;
                    cemiframe->tpci |= (A_READ_VALUE_REQ & 0x03); // !!! maybe wrong
                    cemiframe->apci  = (A_READ_VALUE_REQ & 0xff);
                    socketcon[socketid].response_outstanding = true;
                    break;
                case SOCKET_CMD_WRITE:
                case SOCKET_CMD_WRITE_ONCE:
                    cemiframe->length = len;
                    cemiframe->tpci |= (A_WRITE_VALUE_REQ & 0x03);
                    if( len == 1 ) {
                        cemiframe->apci |= (A_WRITE_VALUE_REQ & 0xc0);
                    } else {
                        cemiframe->apci  = (A_WRITE_VALUE_REQ & 0xff);
                    }
                    if( returnResult( socketid, req_header.cmd, 0 ) != 0 ) {
                        logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                        terminateConnection( socketid );        // does not return
                    }
                    break;
            }
            len += 10;
            hdump = hexdump( THIS_MODULE, cemiframe, sizeof( CEMIFRAME ) -17 + cemiframe->length /* sizeof( CEMIFRAME ) + 6 */ );
            logDebug( THIS_MODULE, "Connection %d: Cemi frame: %s", socketid, hdump );
            free( hdump );
            // and finally, forward it
            logDebug( THIS_MODULE, "Connection %d: Add tunneling request to client queue", socketid );
            addRequestToQueue( THIS_MODULE, &eibQueueClient, buf, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) -17 + cemiframe->length /* sizeof( CEMIFRAME ) + 6 */ );
            pth_cond_notify( &condQueueClient, TRUE );
    
            if( req_header.cmd == SOCKET_CMD_WRITE_ONCE ) {
                terminateConnection( socketid );
            }
        } else if( req_header.cmd == SOCKET_CMD_PASSTHROUGH ) {
            /*
             * handle passthrough operations
             *      req_header.address      device physical address
             *      data                    number of data bytes    (1 byte)
             *                              priority                (1 byte)
             *                              tpci / apci             (2 bytes)
             *                              data                    (x-1 bytes, first "counted" byte is apci)
             */
            // check authorisation
            if( checkAuthorisation( socketid, authPassthrough )) {
                logVerbose( THIS_MODULE, msgSocketCommand, socketid, "passthrough", ntohs( req_header.address ));
                len = 0;
                socketcon[socketid].knxaddress = req_header.address;
            } else {
                logVerbose( THIS_MODULE, msgSocketUnauthorised, socketid, "passthrough" );
                if( returnResult( socketid, SOCKET_STAT_ERROR, E_UNAUTHORISED ) != 0 ) {
                    logError( THIS_MODULE, msgSocketSendAborted, socketid, strerror( errno ));
                    terminateConnection( socketid );        // does not return
                }
                socketcon[socketid].type = 0;
                continue;
            }
            // read operation parameters
            if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, &passthrough, sizeof( passthrough ), sizeof( passthrough ), SOCKET_REQ_TIMEOUT ) != 0 ) {
                terminateConnection( socketid );        // never returns
            }
            
            // create eibnet/ip tunneling request
            // put it on our client's forwarder queue
            // format of request: eibnetip header, connection header, cemi frame, data
            // eibnetip header and connection header will be filled in by forwarder thread, just leave enough room
            // CEMI data is read from client (length bytes)
            // memory will be freed by eibnet/ip client when it releases the queued entry
            buf = allocMemory( THIS_MODULE, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            memset( buf, '\0', sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) + 6 );
            if( passthrough.length > 1 ) {
                if( readFromSocket( THIS_MODULE, socketcon[socketid].socket, socketid, &buf[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + 11] /* start of data in cemiframe */, passthrough.length -1, passthrough.length -1, SOCKET_REQ_TIMEOUT ) != 0 ) {
                    terminateConnection( socketid );        // never returns
                }
            }
            
            // build cemi frame
            cemiframe = (CEMIFRAME *) &buf[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];
            cemiframe->code   = L_DATA_REQ;
            cemiframe->zero   = 0;
            cemiframe->ctrl   = EIB_CTRL_DATA | EIB_CTRL_LENGTHBYTE | EIB_CTRL_NOREPEAT | EIB_CTRL_NONACK | ((passthrough.priority <<2) & 0x0c);
            cemiframe->ntwrk  = EIB_DAF_PHYSICAL | 0X60 /*  EIB_NETWORK_HOPCOUNT */;
            cemiframe->saddr  = /* htons( eibcon[0].knxaddress ) */ 0;
            cemiframe->daddr  = socketcon[socketid].knxaddress;
            cemiframe->length = passthrough.length & 0x0f;
            cemiframe->tpci   = passthrough.tpci;
            if( passthrough.length > 0 ) {
                cemiframe->apci = passthrough.apci;
            }
            
            hdump = hexdump( THIS_MODULE, cemiframe, sizeof( CEMIFRAME ) -17 + cemiframe->length /* exact data size */ );
            logDebug( THIS_MODULE, "Connection %d: Cemi frame: %s", socketid, hdump );
            free( hdump );
            // and finally, forward it
            logDebug( THIS_MODULE, "Connection %d: Add tunneling request to client queue", socketid );
            addRequestToQueue( THIS_MODULE, &eibQueueClient, buf, sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) + sizeof( CEMIFRAME ) -17 + cemiframe->length );
            pth_cond_notify( &condQueueClient, TRUE );
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * SocketFromBusForward thread
 * 
 * our eibnet/ip client puts tunneling requests it receives from the remote server on our queue
 * this thread forwards them to all the connected socket clients
 *   wait for request to be put on queue
 *   for a new request, send it to all connected clients
 */
void *SocketFromBusForward( void *arg )
{
    CEMIFRAME           *cemiframe;
    EIBNETIP_QUEUE      *queue;
    SOCKET_RSP_HEAD     rsp_header;
    pth_event_t         ev_wakeup;
    sigset_t            signal_set;
    uint8_t             loop;
    time_t              secs;
    int                 offset;
    boolean             forward;
    unsigned char       *ptr = NULL;
    char                *hdump;

    logDebug( THIS_MODULE, "Forwarder thread started" );

    // check if we have been started more than once
    pth_mutex_acquire( &mtxSocketForwarder, FALSE, NULL );
    if( tid_frombus != 0 ) {
        logWarning( THIS_MODULE, msgSocketThreadTwice );
    }
    tid_frombus = pth_self();
    pth_mutex_release( &mtxSocketForwarder );
    
    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    secs = time( NULL ) +1;
    pth_mutex_init( &mtxQueueSockets );
    pth_cond_init( &condQueueSocket );
    
    while( true ) {
        // wait for request to be put on queue
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
        
        /*
         * mutex and cond is shared between eibnet/ip and tcp socket servers
         * as they use the same queue
         */
        pth_mutex_acquire( &mtxQueueServer, FALSE, NULL );
        pth_cond_await( &condQueueServer, &mtxQueueServer, ev_wakeup );
        pth_mutex_release( &mtxQueueServer );
        // logDebug( THIS_MODULE, "Wake-up call %d", time( NULL ));
        if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
            // logDebug( THIS_MODULE, "New entry on forwarder queue" );
        }
        pth_event_free( ev_wakeup, PTH_FREE_ALL );
        
        // handle all pending requests
        for( queue = eibQueueServer; queue != NULL;  ) {
            logDebug( THIS_MODULE, "Queue entry %d @ %08x, pending eibnet = %02x, others = %02x", queue->nr, queue, queue->pending_eibnet, queue->pending_others );
            if( queue->pending_others & QUEUE_PENDING_SOCKET ) {
                if( socketcon != NULL ) {
                    // send or re-send request to selected connections
                    for( loop = 0; loop < config.socketclients; loop++ ) {
                        // send only on active connections
                        if( socketcon[loop].socket != 0 ) {
                            forward = true;
                            offset = sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
                            cemiframe = (CEMIFRAME *) &(queue->data[offset]);
                            switch( socketcon[loop].type  ) {
                                default:
                                case SOCKET_CMD_WRITE:
                                case SOCKET_CMD_WRITE_ONCE:
                                    forward = false;                // no packets forwarded
                                    break;
                                case SOCKET_CMD_READ:
                                case SOCKET_CMD_READ_ONCE:
                                    // check if knx address matches
                                    if( socketcon[loop].response_outstanding == true &&
                                        cemiframe->code == L_DATA_IND &&
                                        cemiframe->daddr == socketcon[loop].knxaddress &&
                                        cemiframe->ntwrk & EIB_DAF_GROUP ) {
                                            // send just the data (apci)
                                            offset += 10;
                                            ptr = &cemiframe->apci;
                                            socketcon[loop].response_outstanding = false;
                                    } else {
                                            forward = false;
                                    }
                                    rsp_header.status = SOCKET_STAT_READ;
                                    break;
                                case SOCKET_CMD_MONITOR:
                                    // send the full eib frame if mask matches
                                    if( (cemiframe->daddr & socketcon[loop].knxaddress) != 0 ) {
                                        forward = false;
                                    }
                                    ptr = (unsigned char *)cemiframe;
                                    rsp_header.status = SOCKET_STAT_MONITOR;
                                    break;
                                case SOCKET_CMD_PASSTHROUGH:
                                    ptr = (unsigned char *)knx_physical( THIS_MODULE, cemiframe->saddr );
                                    logDebug( THIS_MODULE, "Connection %d: Examining packet - physical %s, source %s",
                                              loop, ( (cemiframe->ntwrk & 0x80) != EIB_DAF_PHYSICAL ) ? "no" : "yes",
                                              ptr );
                                    free( ptr );
                                    // wait for specific answer
                                    if( (cemiframe->ntwrk & 0x80) != EIB_DAF_PHYSICAL ) {
                                        // must be a packet addressed to a physical device
                                        forward = false;                // no packets forwarded
                                    } else if( cemiframe->saddr != socketcon[loop].knxaddress ) {
                                        // must come from specific device
                                        // could also check, if it is addressed to us
                                        forward = false;                // no packets forwarded
                                    }
                                    ptr = (unsigned char *)cemiframe;
                                    rsp_header.status = SOCKET_STAT_PASSTHROUGH;
                                    break;
                            }
                            // forward request
                            if( forward == true ) {
                                rsp_header.size = htons( queue->len - offset );
                                hdump = hexdump( THIS_MODULE, ptr, queue->len - offset );
                                logTraceSocket( THIS_MODULE, msgSocketForward, loop, hdump );
                                free( hdump );
                                if( pth_write( socketcon[loop].socket, &rsp_header, sizeof( rsp_header )) != sizeof( rsp_header ) || 
                                    pth_write( socketcon[loop].socket, ptr, queue->len - offset ) != queue->len - offset ) {
                                    logError( THIS_MODULE, msgSocketSendAborted, loop, strerror( errno ));
                                    close( socketcon[loop].socket );
                                    if( socketcon[loop].threadid != 0 ) pth_abort( socketcon[loop].threadid );
                                    socketClearConnection( loop );
                                }
                                socketcon[loop].statsPacketsSent++;
                                statsTotalSent++;
                                if( socketcon[loop].type == SOCKET_CMD_READ_ONCE ) {
                                    close( socketcon[loop].socket );
                                    if( socketcon[loop].threadid != 0 ) pth_abort( socketcon[loop].threadid );
                                    socketClearConnection( loop );
                                }
                            }
                        }
                        pth_yield( NULL );
                    }
                }
            }
            
            // mark socket connections as done
            queue->pending_others &= ~QUEUE_PENDING_SOCKET;

            // remove request from queue
            if( queue->pending_others == 0 && queue->pending_eibnet == 0 ) {
                eibQueueServer = removeRequestFromQueue( THIS_MODULE, eibQueueServer );                // assumes that only first queue entry can ever be removed
                queue = eibQueueServer;
            } else {
                logDebug( THIS_MODULE, "Go to next queue entry: current=%08x, next=%08x", queue, queue->next );
                queue = queue->next;
            }
        }
        
        // wake up every 15 seconds
        secs = time( NULL ) + 15;
        // logDebug( THIS_MODULE, "Next wake-up call @ %d", secs );
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * SocketTCP thread
 * 
 * wait for connection requests by special tcp/ip clients
 * spawn new thread for each client
 */
void *SocketTCP( void *arg )
{
    sThreadArgs             *threadargs;
    struct sockaddr_in      server, client;
    struct protoent         *proto_entry;
    pth_attr_t              thread_attr = pth_attr_new();
    sigset_t                signal_set;
    int                     sock_con;
    int                     addr_len;
    int                     tmp;
    char                    ip_text[BUFSIZE_IPADDR];
    sSecurityAddr           *p_secAddr;
    
    logInfo( THIS_MODULE, msgStartupTCPServer );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    /*
     * initialize socket table
     */
    if( socketTable_initialized == false ) {
        // create socketcon array
        socketcon = allocMemory( THIS_MODULE, config.socketclients * sizeof( SOCKET_INFO ));
        
        for( tmp = 0; tmp < config.socketclients; tmp++ ) {
            socketClearConnection( tmp );
        }
        socketTable_initialized = true;
    }
    
    /*
     * register shutdown callback handler to clean up
     */
    tid_tcp = pth_self();
    callbacks[shutdownSocketServer].func = serverShutdown;
    callbacks[shutdownSocketServer].flag = 1;
    
#ifdef WITH_AUTHENTICATION
    /*
     * initialise random number generator for polarssl crypto library
     */
    if( polarssl_hs == NULL ) {
        polarssl_hs = allocMemory( THIS_MODULE, sizeof( havege_state ));
        havege_init( polarssl_hs );
    }
#endif
    
    /*
     * start forwarder thread
     */
    if( tid_frombus == 0 ) {
        pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "SocketFromBusForward" );
        if( pth_spawn( thread_attr, SocketFromBusForward, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread );
            Shutdown();
        }
    }
            
    /*
     * setup listener
     */
    proto_entry = getprotobyname( "tcp" );
    sock_tcpserver = socket( PF_INET, SOCK_STREAM, proto_entry->p_proto );
    tmp = 1;
    setsockopt( sock_tcpserver, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof( tmp ));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = config.tcp_ip;
    server.sin_port = htons( config.tcp_port );
    bind( sock_tcpserver, (struct sockaddr *)&server, sizeof(struct sockaddr_in) );
            
    if( listen( sock_tcpserver, SOMAXCONN ) != 0 ) {
        logCritical( THIS_MODULE, msgTCPNoListener, strerror( errno ));
        serverShutdown();
    }

    /*
     * Now loop endlessly for connections.
     */
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "SocketHandler" );
    while( true ) {
        /*
         * receive connection
         */
        addr_len = sizeof( client );
        if( ( sock_con = pth_accept( sock_tcpserver, (struct sockaddr *)&client, (socklen_t *)&addr_len )) == -1 ) {
            logError( THIS_MODULE, msgTCPConnection, strerror( errno ));
            continue;
        }
        logVerbose( THIS_MODULE, msgSocketConnection, ip_addr( (uint32_t)client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ));
        
        /*
         * security check
         */
        if( config.secClients != NULL ) {
            for( p_secAddr = config.secClients; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
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
                    close( sock_con );
                    continue;
                } else {
                    logDebug( THIS_MODULE, "Request from %s:%d allowed due to rule %d", ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), p_secAddr->rule );
                }
            }
        }
        
        // start handler thread
        threadargs = allocMemory( THIS_MODULE, sizeof( sThreadArgs ));     // will be freed in SocketHandler()
        threadargs->sock = sock_con;
        if( pth_spawn( thread_attr, SocketHandler, (void *)threadargs ) == NULL ) {
            logError( THIS_MODULE, msgInitThread );
            close( sock_con );
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * SocketUnix thread
 * 
 * wait for connection requests by special unix socket clients
 * spawn new thread for each client
 */
void *SocketUnix( void *arg )
{
    sThreadArgs             *threadargs;
    struct sockaddr_un      server, client;
    pth_attr_t              thread_attr = pth_attr_new();
    sigset_t                signal_set;
    int                     sock_con;
    int                     addr_len;
    int                     i;
    struct stat             stat_buf;
    
    logInfo( THIS_MODULE, msgStartupUnixServer );
    
    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    /*
     * initialize socket table
     */
    if( socketTable_initialized == false ) {
        // create socketcon array
        socketcon = allocMemory( THIS_MODULE, config.socketclients * sizeof( SOCKET_INFO ));
        
        for( i = 0; i < config.socketclients; i++ ) {
            socketClearConnection( i );
        }
        socketTable_initialized = true;
    }
    
    /*
     * register shutdown callback handler to clean up
     */
    tid_unix = pth_self();
    callbacks[shutdownSocketServer].func = serverShutdown;
    callbacks[shutdownSocketServer].flag = 1;
    
#ifdef WITH_AUTHENTICATION
    /*
     * initialise random number generator for polarssl crypto library
     */
    if( polarssl_hs == NULL ) {
        polarssl_hs = allocMemory( THIS_MODULE, sizeof( havege_state ));
        havege_init( polarssl_hs );
    }
#endif
    
    /*
     * start forwarder thread
     */
    if( tid_frombus == 0 ) {
        pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
        pth_attr_set( thread_attr, PTH_ATTR_NAME, "SocketFromBusForward" );
        if( pth_spawn( thread_attr, SocketFromBusForward, NULL ) == NULL ) {
            logFatal( THIS_MODULE, msgInitThread );
            Shutdown();
        }
    }
            
    /*
     * setup listener
     */
    if( (sock_unixserver = socket( PF_UNIX, SOCK_STREAM, 0 )) == -1 ) {
        logDebug( THIS_MODULE, "socket creation failed: %s", strerror( errno ));
    }
    server.sun_family = AF_UNIX;
    strcpy( server.sun_path, config.unix_path );
    if( stat( server.sun_path, &stat_buf ) == 0 ) {
        logCritical( THIS_MODULE, msgUnixFileExists, server.sun_path, errno, strerror( errno ));
        close( sock_unixserver );
        sock_unixserver = 0;
        serverShutdown();
    }
    if( bind( sock_unixserver, (struct sockaddr *)&server, sizeof(struct sockaddr_un) ) != 0 ) {
        logDebug( THIS_MODULE, "bind failed: %s", strerror( errno ));
    }
            
    if( listen( sock_unixserver, SOMAXCONN ) != 0 ) {
        logCritical( THIS_MODULE, msgUnixNoListener, strerror( errno ));
        Shutdown();
    }

    /*
     * Now loop endlessly for connections.
     */
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "SocketHandler" );
    while( true ) {
        /*
         * receive connection
         */
        addr_len = sizeof( client );
        if( ( sock_con = pth_accept( sock_unixserver, (struct sockaddr *)&client, (socklen_t *)&addr_len )) == -1 ) {
            logError( THIS_MODULE, msgUnixConnection, strerror( errno ));
            continue;
        }
        logVerbose( THIS_MODULE, msgSocketConnection, client.sun_path, 0 );

        // start handler thread
        threadargs = allocMemory( THIS_MODULE, sizeof( sThreadArgs ));     // will be freed in SocketHandler()
        threadargs->sock = sock_con;
        if( pth_spawn( thread_attr, SocketHandler, (void *)threadargs ) == NULL ) {
            logError( THIS_MODULE, msgInitThread );
            close( sock_con );
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}
