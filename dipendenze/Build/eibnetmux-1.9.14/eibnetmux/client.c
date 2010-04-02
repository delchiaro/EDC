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
 *   EIBnetClient    establish connection and keep it going
 *   TunnelForward   forward tunneling requests received on server side's EIBnetServer & TCPServer
 *   ReceiverControl receive responses & management requests from remote server
 *   ReceiverData    receive responses & tunneling requests from remote server
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <features.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibnetip_private.h"

#define  THIS_MODULE    logModuleEIBnetClient

//globals
EIBNETIP_QUEUE         *eibQueueClient = NULL;                  // pointer to linked list of tunnel request packets
int                     sock_eibclient_control = 0;             // udp sockets for eibnet/ip tunneling
int                     sock_eibclient_data    = 0;
pth_cond_t              condQueueClient;                        // signals tunneling forwarder on pending requests


// local variables
static uint16_t         udp_port_control;                       // our control connection port, data port is +1
static uint16_t         udp_port_data;                          // our data connection port, should be control port +1
static pth_mutex_t      mtxQueueClient;
static pth_mutex_t      mtxClientInUse;                         // serialize request/ack sequences
static pth_t            tid_heartbeat = 0;
static pth_t            tid_recvcontrol = 0;
static pth_t            tid_recvdata = 0;
static pth_t            tid_fwdclient = 0;
static pth_cond_t       condClientState;                        // signals heartbeat thread about changes of client connection
static pth_mutex_t      mtxClientState;
static uint8_t          clientConnectionActive = TRUE;
static uint32_t         statsTotalSent = 0;                     // statistics
static uint32_t         statsTotalReceived = 0;
static uint16_t         statsHeartbeatsMissed = 0;
static time_t           statsUptime = 0;


/*
 * openSocket
 * 
 * create UDP sockets for control and data connections to remote eibnet/ip server
 */
static int openSocket( struct sockaddr_in *addr, uint16_t port )
{
    int     sock;
    int     r, len;
    char    ip_text[BUFSIZE_IPADDR];
    
    bzero( (void *)addr, sizeof( struct sockaddr_in ));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl( INADDR_ANY );
    addr->sin_port = htons( port );

    sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if( sock < 0 || bind( sock, (struct sockaddr *)addr, sizeof( struct sockaddr_in )) == -1 ) {
        logError( THIS_MODULE, msgEIBnetSocket, errno );
        return( -1 );
    }
    
    len = sizeof( struct sockaddr );
    r = getsockname( sock, (struct sockaddr *)addr, (socklen_t *)&len );
    
    logDebug( THIS_MODULE, "opened socket on %s:%d", ip_addr( addr->sin_addr.s_addr, ip_text ), ntohs( addr->sin_port ));

    return( sock );
}


/*
 * setupReceiver
 * 
 * setup the structure which addresses the receiver
 */
static void setupReceiver( void )
{
    // prepare receiver information
    eibcon[0].hpai.structlength = sizeof( EIBNETIP_HPAI );
    eibcon[0].hpai.hostprotocol = IPV4_UDP;
    eibcon[0].hpai.ip           = config.eibServerIP;
    eibcon[0].hpai.port         = config.eibServerPort;
}


/*
 * clientHeartbeat
 * 
 * send ConnectionState request to remote EIBnet/IP server
 * correct answer implies successfull heartbeat
 */
static void clientHeartbeat( void )
{
    EIBNETIP_CONNECTSTATE_REQUEST           *request;             // connect request

    if( eibcon[0].channelid == 0 ) {
        // no connection to remote server
        // probably was disconnected while we slept and waited for next hearbeat interval
        return;
    }
    
    logDebug( THIS_MODULE, "Heartbeat" );

    request = allocMemory( THIS_MODULE, sizeof( EIBNETIP_CONNECTSTATE_REQUEST ));
    
    // prepare control & data hpai endpoints
    request->endpoint.structlength = sizeof( EIBNETIP_HPAI );        // struct_length
    request->endpoint.hostprotocol = IPV4_UDP;
    request->endpoint.ip           = eibcon[0].ipSource;
    request->endpoint.port         = htons( udp_port_control );

    // prepare connection request data
    request->channelid             = eibcon[0].channelid;
    request->reserved              = 0;
    
    // send request
    pth_mutex_acquire( &mtxClientInUse, FALSE, NULL );
    eibcon[0].statsPacketsSent++;
    statsTotalSent++;
    eibNetIpSendControl( EIBNETIP_CLIENT, &eibcon[0], &eibcon[0].hpai, CONNECTIONSTATE_REQUEST, (uint8_t *)request, sizeof( EIBNETIP_CONNECT_REQUEST ));
    pth_mutex_release( &mtxClientInUse );

    free( request );
}

/*
 * clientConnect
 * 
 * connect to remote EIBnet/IP server
 */
static int clientConnect( uint8_t type )
{
    EIBNETIP_CONNECT_REQUEST    *request;             // connect request
    char                        ip_text[BUFSIZE_IPADDR];
    int                         r;

    if( eibcon[0].channelid != 0 ) {
        logDebug( THIS_MODULE, "clientConnect() called on established connection (id=%d instead of 0)", eibcon[0].channelid );
    }
    
    eibNetClearConnection( &eibcon[0] );
    setupSignalling( THIS_MODULE, 0 );

    // prepare receiver information
    setupReceiver();

    logDebug( THIS_MODULE, "Trying to establish tunneling connection (type %02x) with remote server @ %s", type, ip_addr( eibcon[0].hpai.ip, ip_text ));

    // get my ip address for targeted server
    if( (r = network_getsourceaddress( eibcon[0].hpai.ip, &eibcon[0].ipSource )) != 0 ) {
        logFatal( THIS_MODULE, msgEIBnetClientNoAddress, r );
        Shutdown();
    }
    eibcon[0].ipPort = htons( udp_port_data );
    logDebug( THIS_MODULE, "My address: %s, control port: %d, data port: %d", ip_addr( eibcon[0].ipSource, ip_text ), udp_port_control, udp_port_data );
    
    request = allocMemory( THIS_MODULE, sizeof( EIBNETIP_CONNECT_REQUEST ));
    
    // prepare control & datat hpai endpoints
    request->control_endpoint.structlength = sizeof( EIBNETIP_HPAI );        // struct_length
    request->control_endpoint.hostprotocol = IPV4_UDP;
    memcpy( &request->control_endpoint.ip, &eibcon[0].ipSource, sizeof( request->control_endpoint.ip ));
    request->control_endpoint.port         = htons( udp_port_control );
    request->data_endpoint.structlength    = sizeof( EIBNETIP_HPAI );
    request->data_endpoint.hostprotocol    = IPV4_UDP;
    memcpy( &request->data_endpoint.ip, &eibcon[0].ipSource, sizeof( request->data_endpoint.ip ));
    request->data_endpoint.port            = htons( udp_port_data );

    // prepare connection request data
    request->crd.structlength              = 4;
    request->crd.connectiontypecode        = TUNNEL_CONNECTION;
    request->crd.protocolindependentdata   = type;
    request->crd.protocoldependentdata     = 0;
    config.tunnelmode = type;
    
    // send request
    pth_mutex_acquire( &mtxClientInUse, FALSE, NULL );
    eibcon[0].statsPacketsSent++;
    statsTotalSent++;
    r = eibNetIpSendControl( EIBNETIP_CLIENT, &eibcon[0], &eibcon[0].hpai, CONNECT_REQUEST, (uint8_t *)request, sizeof( EIBNETIP_CONNECT_REQUEST ));
    pth_mutex_release( &mtxClientInUse );
    
    free( request );
    
    if( r == 0 ) {
        if( eibcon[0].status == E_NO_ERROR ) {
            statsUptime = time( NULL );
            return( 0 );
        } else {
            return( -1  );
        }
    } else {
        return( -1 );
    }
}


/*
 * clientDisconnect
 * 
 * disconnect from remote EIBnet/IP server
 */
static void clientDisconnect( char *reason )
{
    EIBNETIP_HEADER                 *request;             // disconnect request
    EIBNETIP_DISCONNECT_REQUEST     *disconn;
    uint16_t                        length;
    
    if( eibcon[0].channelid == 0 ) {
        logDebug( THIS_MODULE, "Disconnecting from unestablished connection" );
        return;
    }
    
    logDebug( THIS_MODULE, "clientDisconnect( %s )", reason );
    
    // in loopback mode, don't disconnect as server has been downed already
    if( eibcon[0].loopback != loopbackOn ) {
        length = sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_DISCONNECT_REQUEST );
        request = allocMemory( THIS_MODULE, length );
        
        // prepare packet
        disconn = (EIBNETIP_DISCONNECT_REQUEST *) request;
        disconn->channelid = eibcon[0].channelid;
        disconn->status    = E_NO_ERROR;
        disconn->control_endpoint.structlength = sizeof( EIBNETIP_HPAI );        // struct_length
        disconn->control_endpoint.hostprotocol = IPV4_UDP;
        disconn->control_endpoint.ip           = eibcon[0].ipSource;
        disconn->control_endpoint.port         = htons( udp_port_control );
        
        // do NOT lock the connection here
        // mutex may still be locked if we are called in case of an error
        // just "abort" the connection
        statsTotalSent++;
        eibNetIpSendControl( EIBNETIP_CLIENT, &eibcon[0], &eibcon[0].hpai, DISCONNECT_REQUEST, (uint8_t *)request, length );
        statsUptime = 0;
        
        free( request );
    }
    
    eibNetClearConnection( &eibcon[0] );
}


/*
 * Shutdown handler
 * - disconnect from remote server
 * - close sockets
 * 
 * this is executed as thread main
 */
static void clientShutdown( void )
{
    callbacks[shutdownEIBnetClient].flag = 0;

    // kill threads so we don't initiate any new actions
    if( tid_fwdclient != 0 ) pth_abort( tid_fwdclient );    // !!! maybe should use pth_cancel and set cancellation points in forwarder
    if( tid_heartbeat != 0 ) pth_abort( tid_heartbeat );
    if( tid_recvdata != 0 ) pth_abort( tid_recvdata );

    clientDisconnect( "shutdown" );

    if( tid_recvcontrol != 0 ) pth_abort( tid_recvcontrol );

    close( sock_eibclient_control );
    close( sock_eibclient_data );

    logInfo( THIS_MODULE, msgShutdown );
}


/*
 * Switch conncetion type
 */
void EIBnetClientSwitchConnectionType( uint8_t type )
{
    if( config.tunnelmode == type ) {
        return;
    }
    
    logDebug( THIS_MODULE, "Switching connection type: %02x --> %02x", config.tunnelmode, type );
    
    clientDisconnect( "Switching connection type" );
    clientConnect( type );
    if( type == TUNNEL_BUSMONITOR ) {
        logWarning( THIS_MODULE, msgEIBnetMonitorActive );
    }
}


/*
 * EIBnetTunnelForward thread
 * 
 * our eibnet/ip server puts tunneling requests it receives on the client queue
 * this thread forwards them to the remote server and removes them from the queue
 */
void *EIBnetTunnelForward( void *arg )
{
    EIBNETIP_COMMON_CONNECTION_HEADER       *conn_head;
    CEMIFRAME                               *cemiframe;
    pth_event_t                             ev_wakeup;
    sigset_t                                signal_set;
    unsigned char                           *request;
    unsigned char                           *data_buffer;
    int                                     length;
    time_t                                  secs;

    logDebug( THIS_MODULE, "EIBnetTunnelForward" );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    pth_mutex_init( &mtxQueueClient );
    pth_cond_init( &condQueueClient );
    while( true ) {
        // wait for request to be put on queue
        secs = time( NULL ) +1;
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
        pth_mutex_acquire( &mtxQueueClient, FALSE, NULL );
        pth_cond_await( &condQueueClient, &mtxQueueClient, ev_wakeup );
        pth_mutex_release( &mtxQueueClient );
        if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
            logDebug( THIS_MODULE, "Entry found on forwarder queue" );
        }
        pth_event_free( ev_wakeup, PTH_FREE_ALL );
        
        while( eibQueueClient != NULL ) {
            if( eibcon[0].channelid != 0 ) {
                // we have an established connection to the remote server
                if( eibcon[0].loopback == loopbackOn ) {
                    // in loopback mode, there is no need to forward request
                    // it would go to our own server which forwards it to this thread, creating an endless loop
                    // instead, simply assume it was received from the upstream server and forward it accordingly
                    // there is also no need to call the eibnet/ip protocol handler as 
                    // 1) this has just been done before the request was put on our queue
                    // 2) it can only be a tunneling request anyway
                    
                    logDebug( THIS_MODULE, "Loopback mode - immediately put request on forwarder queue." );
                    data_buffer = allocMemory( THIS_MODULE, eibQueueClient->len );
                    memcpy( data_buffer, eibQueueClient->data, eibQueueClient->len );
                    
                    // convert L_DATA_REQ to L_DATA_CON
                    cemiframe = (CEMIFRAME *) &data_buffer[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )];
                    if( cemiframe->code == L_DATA_REQ ) {
                        cemiframe->code = L_DATA_CON;
                        cemiframe->ctrl |= EIB_CTRL_NONACK + 0x01;      // don't know what the 0x01 means
                        cemiframe->saddr = 0x0111;                      // we always assign ourself KNX physical address 1.1.1
                    }
                    
                    addRequestToQueue( THIS_MODULE, &eibQueueServer, data_buffer, eibQueueClient->len );
                    pth_cond_notify( &condQueueServer, TRUE );
                } else {
                    // prepare connection header
                    length = eibQueueClient->len - sizeof( EIBNETIP_HEADER );
                    request = allocMemory( THIS_MODULE, length );
                    conn_head = (EIBNETIP_COMMON_CONNECTION_HEADER *) request;
                    conn_head->structlength    = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
                    conn_head->channelid       = eibcon[0].channelid;
                    conn_head->sequencecounter = eibcon[0].sequencecounter_sent;
                    conn_head->status          = E_NO_ERROR;
                    
                    // add tunnel data to request packet
                    memcpy( &request[sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )],
                            &eibQueueClient->data[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ) /* -1 */],
                            length - sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ));
            
                    // finally, send tunneling request
                    pth_mutex_acquire( &mtxClientInUse, FALSE, NULL );
                    eibcon[0].statsPacketsSent++;
                    statsTotalSent++;
                    if( eibNetIpSendData( EIBNETIP_CLIENT, &eibcon[0], &eibcon[0].hpai, TUNNELLING_REQUEST, request, length ) != 0 ) {
                        clientDisconnect( "forwarder" );
                    }
                    pth_mutex_release( &mtxClientInUse );
                }
            }
            
            eibQueueClient = removeRequestFromQueue( THIS_MODULE, eibQueueClient );                // assumes that only first queue entry can ever be removed
            pth_yield( NULL );
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * EIBnetClientReceiverData thread
 * 
 * listen on data connection UDP port and handle incoming requests
 */
void *EIBnetClientReceiverData( void *arg )
{
    sigset_t                signal_set;
    struct sockaddr_in      server;
    int                     addrlen;
    int                     len;
    unsigned char           *buf = NULL;
    char                    *dump;
    char                    ip_text[BUFSIZE_IPADDR];
    
    logDebug( THIS_MODULE, "EIBnetClientReceiverData" );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    addrlen = sizeof( server );

    while( true ) {
        // the request buffer - will be freed by eibServerForward
        if( buf == NULL ) {
            buf = allocMemory( THIS_MODULE, EIBNETIP_FRAME_SIZE );                     // too big ??? !!!
        }
        bzero( (void *)&server, sizeof( server ));

        while( true ) {
            pth_yield( NULL );
            len = pth_recvfrom( sock_eibclient_data, (void*)buf, EIBNETIP_FRAME_SIZE, 0, (struct sockaddr*)&server, (socklen_t *)&addrlen );
            logDebug( THIS_MODULE, "Got %d bytes on data connection", len );
            if( len >= EIBNETIP_FRAME_SIZE ) {
                logDebug( THIS_MODULE, "Maximum frame size matched or exceeded (%d bytes)", len );
            }
            if( len == -1 && errno == EAGAIN ) {
                continue;
            } else if( len > 0 ) {
                break;
            }
        }
        
        dump = hexdump( EIBNETIP_CLIENT, buf, len );
        logTraceClient( EIBNETIP_CLIENT, msgFrameReceived, ip_addr( server.sin_addr.s_addr, ip_text ), ntohs( server.sin_port ), dump );
        free( dump );
        
        eibcon[0].statsPacketsReceived++;
        statsTotalReceived++;
        if( len >= 0 ) {
            if( EIBnetIPProtocolHandler( EIBNETIP_CLIENT, buf, len, secAddrTypeAllow ) > 0 ) {
                // request has not finished completely
                // allocate new buffer
                // old one will/must be freed by other code (e.g. eibTunnelForward)
                buf = NULL;
            }
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}

/*
 * EIBnetClientReceiverControl thread
 * 
 * listen on control connection UDP port and handle incoming requests
 */
void *EIBnetClientReceiverControl( void *arg )
{
    sigset_t                signal_set;
    struct sockaddr_in      server;
    int                     addrlen;
    int                     len;
    unsigned char           *buf = NULL;
    char                    *dump;
    char                    ip_text[BUFSIZE_IPADDR];
    
    logDebug( THIS_MODULE, "EIBnetClientReceiverControl" );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    addrlen = sizeof( server );

    while( true ) {
        // the request buffer - will be freed by eibServerForward
        if( buf == NULL ) {
            buf = allocMemory( THIS_MODULE, EIBNETIP_FRAME_SIZE );                     // too big ??? !!!
        }
        bzero( (void *)&server, sizeof( server ));

        while( true ) {
            pth_yield( NULL );
            len = pth_recvfrom( sock_eibclient_control, (void*)buf, EIBNETIP_FRAME_SIZE, 0, (struct sockaddr*)&server, (socklen_t *)&addrlen );
            logDebug( THIS_MODULE, "Got %d bytes on control connection", len );
            if( len >= EIBNETIP_FRAME_SIZE ) {
                logDebug( THIS_MODULE, "Maximum frame size matched or exceeded (%d bytes)", len );
            }
            if( len == -1 && errno == EAGAIN ) {
                continue;
            } else if( len > 0 ) {
                break;
            }
        }
        
        dump = hexdump( EIBNETIP_CLIENT, buf, len );
        logTraceClient( EIBNETIP_CLIENT, msgFrameReceived, ip_addr( server.sin_addr.s_addr, ip_text ), ntohs( server.sin_port ), dump );
        free( dump );
        
        eibcon[0].statsPacketsReceived++;
        statsTotalReceived++;
        if( len >= 0 ) {
            if( EIBnetIPProtocolHandler( EIBNETIP_CLIENT, buf, len, secAddrTypeAllow ) > 0 ) {
                // request has not finished completely
                // allocate new buffer
                // old one will/must be freed by other code (e.g. eibTunnelForward)
                buf = NULL;
            }
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}

/*
 * EIBnetClientStatus
 * 
 * Return current connection status:
 *      (length of structure)
 *      1: connection state, uptime, packets received/sent for this connection,
 *         packets received/sent since startup,
 *         length of sender queue, number of missed hearbeats
 *         source ip used to connect to server
 *      2: connection state, uptime, packets received/sent for this connection,
 *         packets received/sent since startup,
 *         length of sender queue, number of missed hearbeats
 *         2 bytes of source ip
 *      3: connection state, uptime, packets received/sent for this connection,
 *         packets received/sent since startup,
 *         length of sender queue, number of missed hearbeats
 *         name of target, ip of target, port of target, source ip used to connect to server
 *      4: connection state, uptime, packets received/sent for this connection,
 *         packets received/sent since startup,
 *         length of sender queue, number of missed hearbeats
 *         name of target, ip of target, port of target, source ip used to connect to server
 *         loopback mode
 */
char *EIBnetClientStatus( void )
{
    EIBNETIP_QUEUE  *queue;
    char            *status;
    uint16_t        statsQueueWaiting;
    uint16_t        tmp16;
    uint16_t        idx;
    uint8_t         namelength;
    
    statsQueueWaiting = 0;
    for( queue = eibQueueClient; queue != NULL; queue = queue->next ) {
        statsQueueWaiting++;
    }
    
#define STATUS_CLIENT_VERSION     4
#define STATUS_CLIENT_BASE_LENGTH   41
    namelength = strlen( config.eibConnectionParam );
    tmp16 = STATUS_CLIENT_BASE_LENGTH + namelength;
    status = allocMemory( THIS_MODULE, 2 + tmp16 );
    idx = 0;
    idx = AppendBytes( idx, status, sizeof( tmp16 ), tmp16 );   // used internally, indicates size of buffer
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( tmp16 ));
    idx = AppendBytes( idx, status, 1, STATUS_CLIENT_VERSION );
    idx = AppendBytes( idx, status, 1, clientConnectionActive );
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( time( NULL ) - statsUptime ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibcon[0].statsPacketsReceived ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibcon[0].statsPacketsSent ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalReceived ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalSent ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( statsQueueWaiting ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( statsHeartbeatsMissed ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( namelength ));
    memcpy( &status[idx], config.eibConnectionParam, namelength );
    idx += namelength;
    idx = AppendBytes( idx, status, sizeof( uint32_t ), eibcon[0].hpai.ip );
    idx = AppendBytes( idx, status, sizeof( uint16_t ), eibcon[0].hpai.port );
    idx = AppendBytes( idx, status, sizeof( uint32_t ), eibcon[0].ipSource );
    idx = AppendBytes( idx, status, sizeof( uint8_t ), eibcon[0].loopback );
    logDebug( THIS_MODULE, "Client status: %s", hexdump( THIS_MODULE, status +2, STATUS_CLIENT_BASE_LENGTH + namelength ));
    return( status );
}

/*
 * EIBnetClientSetState
 * 
 * Client can be either enabled or suspended. In the latter case,
 * it disconnects from the remote server. This can be used if
 * another software (e.g. ETS3) needs a direct connection to the
 * remote server.
 * If the state changes, the heartbeat thread is signalled to
 * either connect or disconnect.
 * 
 * Input:       0 - suspend connection
 *              1 - activate connection
 */
void EIBnetClientSetState( uint8_t newstate )
{
    if( newstate == 1 ) newstate = TRUE;
    else if( newstate == 0 ) newstate = FALSE;
    else newstate = clientConnectionActive;
    
    if( clientConnectionActive != newstate ) {
        clientConnectionActive = newstate;
        pth_cond_notify( &condClientState, TRUE );
    }
}

/*
 * EIBnetClient thread
 * 
 * create an EIBnet/IP tunneling session
 * start receiver thread
 * implement heartbeat
 *      the tunneling session needs to be kept alive by sending a ConnectionStatus request
 *      at least every 60 seconds
 *      if two hearbeats are missed in a row, consider server down/unreachable and mark connection closed
 */
void *EIBnetClient( void *arg )
{
    pth_attr_t              thread_attr;
    pth_event_t             ev_heartbeat;
    pth_time_t              nap_time;
    time_t                  secs;
    sigset_t                signal_set;
    struct sockaddr_in      addr_control, addr_data;
    long                    retry_wait;
    int                     retry;
    int                     result;

    logInfo( THIS_MODULE, msgStartupEIBClient );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    pth_mutex_init( &mtxClientState );
    pth_cond_init( &condClientState );

    // open sockets for EIBnet/IP tunneling connection
    sock_eibclient_control = openSocket( &addr_control, 0 );
    udp_port_control = ntohs( addr_control.sin_port );
    sock_eibclient_data = openSocket( &addr_data, 0 );
    udp_port_data = ntohs( addr_data.sin_port );
    if( sock_eibclient_control < 0 || sock_eibclient_data < 0 ) {
        logFatal( THIS_MODULE, msgEIBnetSocket );
        Shutdown();
    }

    /*
     * register shutdown callback handler to clean up
     */
    tid_heartbeat = pth_self();
    callbacks[shutdownEIBnetClient].func = clientShutdown;
    callbacks[shutdownEIBnetClient].flag = 1;

    /*
     * setup thread attributes
     */
    thread_attr = pth_attr_new();
    pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
    pth_mutex_init( &mtxClientInUse );
    
    /*
     * start receiver and forwarder threads
     */
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetClientReceiverControl" );
    if( (tid_recvcontrol = pth_spawn( thread_attr, EIBnetClientReceiverControl, NULL )) == NULL ) {
        logFatal( THIS_MODULE, msgInitThread );
        Shutdown();
    }
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetClientReceiverData" );
    if( (tid_recvdata = pth_spawn( thread_attr, EIBnetClientReceiverData, NULL )) == NULL ) {
        logFatal( THIS_MODULE, msgInitThread );
        Shutdown();
    }
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetClientForward" );
    if( (tid_fwdclient = pth_spawn( thread_attr, EIBnetTunnelForward, NULL )) == NULL ) {
        logFatal( THIS_MODULE, msgInitThread );
        Shutdown();
    }
    
    // establish connection to server
    while( true ) {
        // wait until connection is enabled
        // (it is by default but can be suspended using the management interface)
        while( clientConnectionActive == FALSE ) {
            pth_mutex_acquire( &mtxClientState, FALSE, NULL );
            pth_cond_await( &condClientState, &mtxClientState, NULL );
            pth_mutex_release( &mtxClientState );
            logVerbose( THIS_MODULE, msgEIBnetClientActive );
        }
        retry_wait = 10;
        retry = 0;
        while( eibcon[0].channelid == 0 ) {
            if( clientConnectionActive == FALSE ) {
                break;
            }
            // channelid will be >0 if connection is established to remote server
            // set by EIBnetClientReceiverControl()
            result = clientConnect( TUNNEL_LINKLAYER );
            if( result == 0 ) {
                // connection established
                pth_yield( NULL );
                continue;
            }
            
            /*
             * retry if unsuccessfull
             * clientConnect retries 3 times every 5 seconds
             * we retry every 10 seconds for 6 times
             * after 18 unsuccessfull tries (150 seconds) lengthen our interval to 1 minute
             */
            nap_time = pth_time( retry_wait, 0 );       // $$$ check this, shouldn't retry_time be added to time()
            pth_nap( nap_time );
            if( ++retry > 5 ) retry_wait = 60;
        }
        
        /*
         * heartbeat
         */
        while( eibcon[0].channelid != 0 ) {
            /*
             * wait until next heartbeat needs to be sent
             * in the meantime we should receive the acknowledgement (by EIBnetClientReceiverControl)
             * if not, consider connection broken and close it
             * this thread will then automatically try to re-establish it
             * this thread is also woken up if client connection is suspended
             */
            secs = time( NULL ) + HEARTBEAT_INTERVAL;
            ev_heartbeat = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
            pth_mutex_acquire( &mtxClientState, FALSE, NULL );
            pth_cond_await( &condClientState, &mtxClientState, ev_heartbeat );
            pth_mutex_release( &mtxClientState );
            pth_event_free( ev_heartbeat, PTH_FREE_ALL );
            if( clientConnectionActive == FALSE ) {
                logVerbose( THIS_MODULE, msgEIBnetClientSuspend );
                clientDisconnect( "client deactivated" );
                break;
            }
            
            // pth_nap( pth_timeout( HEARTBEAT_INTERVAL, 0 ));
            if( eibcon[0].counter > 0 ) {
                statsHeartbeatsMissed++;
            }
            if( ++eibcon[0].counter > 2 ) {
                logCritical( THIS_MODULE, msgEIBnetClientHeartbeat );
                clientDisconnect( "missed heartbeat" );
                break;
            }
            clientHeartbeat();
        }
        pth_yield( NULL );
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}
