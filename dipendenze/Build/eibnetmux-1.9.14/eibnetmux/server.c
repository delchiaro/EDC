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
 *   EIBnetServer    receive requests and tunneling responses from EIBnet/IP clients
 *   TunnelForward   forward tunneling requests received by client side's Receiver
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
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibnetip_private.h"

#define  THIS_MODULE    logModuleEIBnetServer

/*
 * Globals
 */
EIBNETIP_QUEUE          *eibQueueServer = NULL;         // pointer to linked list of tunnel request packets
int                      sock_eibserver = 0;            // udp socket receiving eibnet/ip packets
pth_cond_t               condQueueServer;               // signals tunneling forwarder on pending requests
pth_mutex_t              mtxQueueServer;                // corresponding mutex


/*
 * Local variables
 */
static pth_t            tid_receiver = 0;
static pth_t            tid_fwdserver = 0;
static uint32_t         statsTotalSent = 0;                     // statistics
static uint32_t         statsTotalReceived = 0;


/*
 * eibNetServerDistribute
 * 
 * tunneling request was received from eib
 * forward to all connected clients
 * acks are handled by normal receiver eibNetIpServer()
 */
static void eibNetServerDistribute( EIBNETIP_QUEUE *queue, uint8_t connid )
{
    EIBNETIP_COMMON_CONNECTION_HEADER       *conn_head;
    EIBNETIP_HPAI                           hpai_client;
    unsigned char                           *request;
    int                                     length;
    
    // only send to active conncections
    if( eibcon[connid].channelid == 0 ) {
        queue->pending_eibnet &= ~(1 << connid);
        return;
    }

    // prepare request packet
    length = queue->len - sizeof( EIBNETIP_HEADER );
    request = allocMemory( THIS_MODULE, length );
    conn_head = (EIBNETIP_COMMON_CONNECTION_HEADER *) request;
    conn_head->structlength    = sizeof( EIBNETIP_COMMON_CONNECTION_HEADER );
    conn_head->channelid       = eibcon[connid].channelid;
    conn_head->sequencecounter = eibcon[connid].sequencecounter_sent;
    conn_head->status          = E_NO_ERROR;

    // add tunnel data to request packet
    memcpy( &request[sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )],
            &queue->data[sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_COMMON_CONNECTION_HEADER )],
            length - sizeof( EIBNETIP_COMMON_CONNECTION_HEADER ));
    
    // prepare receiver information
    hpai_client.structlength = sizeof( EIBNETIP_HPAI );
    hpai_client.hostprotocol = eibcon[connid].hpai.hostprotocol;
    hpai_client.ip           = eibcon[connid].hpai.ip;
    hpai_client.port         = eibcon[connid].hpai.port;
    
    // finally, send tunneling request without waiting for any response
    statsTotalSent++;
    eibNetIpSend( EIBNETIP_SERVER, sock_eibserver, &hpai_client, TUNNELLING_REQUEST, request, length );

    free( request );
}
 
/*
 * Shutdown handler
 * - disconnect from remote server
 * - close sockets
 * 
 * this is executed as thread main
 */
static void serverShutdown( void )
{
    struct ip_mreqn                 mcfg;
    EIBNETIP_HEADER                 *request;               // disconnect request
    EIBNETIP_DISCONNECT_REQUEST     *disconn;
    uint16_t                        length;
    int                             loop;

    callbacks[shutdownEIBnetServer].flag = 0;
    
    // kill threads so we don't initiate any new actions
    if( tid_fwdserver != 0 ) pth_abort( tid_fwdserver );    // !!! maybe should use pth_cancel and set cancellation points in forwarder
    if( tid_receiver != 0 ) pth_abort( tid_receiver );

    length = sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_DISCONNECT_REQUEST );
    request = allocMemory( THIS_MODULE, length );

    // prepare packet
    disconn = (EIBNETIP_DISCONNECT_REQUEST *) request;
    disconn->status = E_NO_ERROR;
    disconn->control_endpoint.structlength = sizeof( EIBNETIP_HPAI );        // struct_length
    disconn->control_endpoint.hostprotocol = IPV4_UDP;
    disconn->control_endpoint.port         = htons( config.eib_port );

    for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
        if( eibcon[loop].channelid > 0 ) {
            logDebug( THIS_MODULE, "Close connection %d", loop );
            disconn->channelid = eibcon[loop].channelid;
            disconn->control_endpoint.ip = eibcon[loop].ipSource;
            statsTotalSent++;
            (void) eibNetIpSendControl( EIBNETIP_SERVER, NULL, &eibcon[loop].hpai, DISCONNECT_REQUEST, (uint8_t *)request, length );
            eibNetClearConnection( &eibcon[loop] );
        }
    }
    free( request );
    if( sock_eibserver > 0 ) {
        mcfg.imr_multiaddr.s_addr = inet_addr( EIBNETIP_MULTICAST_ADDRESS );
        mcfg.imr_address.s_addr = htonl( INADDR_ANY );
        mcfg.imr_ifindex = 0;
        setsockopt( sock_eibserver, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mcfg, sizeof( mcfg ));
        close( sock_eibserver );
    }
    logInfo( THIS_MODULE, msgShutdown );
}


/*
 * eibServerForward thread
 * 
 * our eibnet/ip client puts tunneling requests it receives from the remote server on the server queue
 * this thread forwards them to all the connected clients
 *   wait for request to be put on queue
 *   for a new request, send it to all connected clients
 *   otherwise, resend every 5 seconds to those clients from which we didn't yet receive the acknowledgement
 *   after 3 sends, remove request from queue and mark client connections as down
 * acknowledgements are received by thread EIBnetServer()
 * communication between the two threads is based on 'pending' flags and connection status
 */
void *EIBnetServerForward( void *arg )
{
    EIBNETIP_QUEUE          *queue;
    pth_event_t             ev_wakeup;
    sigset_t                signal_set;
    uint8_t                 loop;
    connmask_t              pending;
    time_t                  secs;

    logDebug( THIS_MODULE, "Forwarder thread started" );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    secs = time( NULL ) +1;
    while( true ) {
        // wait for request to be put on queue
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
        pth_mutex_acquire( &mtxQueueServer, FALSE, NULL );
        pth_cond_await( &condQueueServer, &mtxQueueServer, ev_wakeup );
        pth_mutex_release( &mtxQueueServer );
        logDebug( THIS_MODULE, "Wake-up call %d", time( NULL ));
        if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
            // logDebug( THIS_MODULE, "Entry found on forwarder queue" );
        }
        pth_event_free( ev_wakeup, PTH_FREE_ALL );
        
        // handle all pending requests
        // we could theoretically apply more intelligence here and only touch those requests
        // which effectively need to be handled
        // however, as most requests are sent only once and then removed from the queue
        // it's not really necessary
        for( queue = eibQueueServer; queue != NULL;  ) {
            logDebug( THIS_MODULE, "Queue entry %d @ %08x, pending eibnet = %02x, others = %02x", queue->nr, queue, queue->pending_eibnet, queue->pending_others );
            // send or re-send request to selected connections
            pending = queue->pending_eibnet;
            if( pending != 0 ) {
                for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
                    pending >>= 1;
                    if( pending == 0 ) {
                        // no need to check more connections
                        break;
                    }
                    
                    // if there is no active connection in this slot or it loops back to our client, mark as sent
                    if( eibcon[loop].channelid == 0 || eibcon[loop].loopback == loopbackOn ) {
                        queue->pending_eibnet &= ~(1 << loop);
                        // logDebug( THIS_MODULE, "Do not send to connection %d", loop );
                    } else if( pending & 0x01 ) {
                        // send request or resend after 5 seconds
                        if( eibcon[loop].nextsend <= time( NULL ) ) {
                            if( eibcon[loop].counter >= MAX_RESENDS ) {
                                // give up after 3 retries,
                                // mark request as done for this connection,
                                // and clear connection
                                queue->pending_eibnet &= ~(1 << loop);
                                eibNetClearConnection( &eibcon[loop] );
                                logDebug( THIS_MODULE, "Connection %d timed out - cleared", loop );
                            } else {
                                // send request
                                // upon receiving the corresponding ack, eibNetIpServer() will clear pending flag of queue
                                logDebug( THIS_MODULE, "%sSend request to connection %d (%d)",
                                          (eibcon[loop].counter == 0) ? "" : "Re-", loop, eibcon[loop].counter );
                                eibNetServerDistribute( queue, loop );
                                eibcon[loop].nextsend = time( NULL ) + ACKNOWLEDGEMENT_TIMEOUT;
                                eibcon[loop].counter++;
                            }
                        }
                    }
                    
                    pth_yield( NULL );
                }
            }
            
            // remove request from queue if
            //      all connections have either acknowledged the request or timed out
            //      no socket or eibd client is pending
            // received acknowledgements are marked in eibNetIpServer()
            if( queue->pending_others == 0 && queue->pending_eibnet == 0 ) {
                eibQueueServer = removeRequestFromQueue( THIS_MODULE, eibQueueServer );                // assumes that only first queue entry can ever be removed
                queue = eibQueueServer;
            } else {
                logDebug( THIS_MODULE, "Go to next queue entry: current=%08x, next=%08x", queue, queue->next );
                queue = queue->next;
            }
        }
        
        // find out when we need to wake up at the latest to resend a request
        // hopefully, that won't be necessary as the acknowledgement has been received by then
        // but you never know
        secs = time( NULL ) + 15;
        for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
            if( eibcon[loop].nextsend > 0 && secs > eibcon[loop].nextsend ) {
                secs = eibcon[loop].nextsend;
            }
        }
        logDebug( THIS_MODULE, "Next wake-up call @ %d", secs );
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}


/*
 * EIBnetServerStatus
 * 
 * Return current connection status:
 *      (length of structure)
 *      1: active, port, max clients, number connected clients,
 *         total packets received/sent, length of sender queue
 *         per connected client:
 *              address, port, packets received/sent, length of sender queue
 *      2: active, port, max clients, number connected clients,
 *         total packets received/sent, length of sender queue
 *         per connected client:
 *              address, port, packets received/sent, length of sender queue, source address (lsb first)
 *      3: active, port, max clients, number connected clients,
 *         total packets received/sent, length of sender queue
 *         per connected client:
 *              address, port, packets received/sent, length of sender queue, source address
 *      4: active, port, max clients, number connected clients,
 *         total packets received/sent, length of sender queue,
 *         default authentication level, access block level
 *         per connected client:
 *              unique connection id, address, port, packets received/sent, length of sender queue, source address
 */
char *EIBnetServerStatus( void )
{
    EIBNETIP_QUEUE  *queue;
    char            *status;
    uint8_t         connectedClients;
    uint16_t        statsQueueWaiting;
    uint16_t        loop;
    uint16_t        tmp16;
    uint16_t        idx;
    
    statsQueueWaiting = 0;
    for( queue = eibQueueServer; queue != NULL; queue = queue->next ) {
        statsQueueWaiting++;
    }
    connectedClients = 0;
    for( loop = 1; loop <= EIBNETIP_MAXCONNECTIONS; loop++ ) {
        if( eibcon[loop].channelid > 0 ) {
            connectedClients++;
        }
    }

#define STATUS_SERVER_VERSION     4
#define STATUS_SERVER_BASE_LENGTH   22
#define STATUS_SERVER_CLIENT_LENGTH 24
    tmp16 = STATUS_SERVER_BASE_LENGTH;
    status = allocMemory( THIS_MODULE, 2 + tmp16 + connectedClients * STATUS_SERVER_CLIENT_LENGTH );
    idx = 0;
    idx = AppendBytes( idx, status, sizeof( tmp16 ), tmp16 + connectedClients * STATUS_SERVER_CLIENT_LENGTH );   // used internally, indicates size of buffer
    idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( tmp16 ));
    idx = AppendBytes( idx, status, 1, STATUS_SERVER_VERSION );
    idx = AppendBytes( idx, status, 1, (config.servers & SERVER_EIBNET) ? 1 : 0 );
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.eib_port ));
    idx = AppendBytes( idx, status, 1, EIBNETIP_MAXCONNECTIONS );
    idx = AppendBytes( idx, status, 1, connectedClients );
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalReceived ));
    idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( statsTotalSent ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( statsQueueWaiting ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.defaultAuthEIBnet ));
    idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( config.maxAuthEIBnet ));

    for( loop = 1; loop <= connectedClients; loop++ ) {
        if( eibcon[loop].channelid > 0 ) {
            // idx = AppendBytes( idx, status, sizeof( tmp16 ), htons( 16 ));
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibcon[loop].connectionid ));
            idx = AppendBytes( idx, status, sizeof( uint32_t ), eibcon[loop].hpai.ip );
            idx = AppendBytes( idx, status, sizeof( uint16_t ), eibcon[loop].hpai.port );
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibcon[loop].statsPacketsReceived ));
            idx = AppendBytes( idx, status, sizeof( uint32_t ), htonl( eibcon[loop].statsPacketsSent ));
            tmp16 = 0;
            for( queue = eibQueueServer; queue != NULL; queue = queue->next ) {
                if( queue->pending_eibnet & (1 << loop) ) { 
                    tmp16++;
                }
            }
            idx = AppendBytes( idx, status, sizeof( uint16_t ), htons( tmp16 ));
            idx = AppendBytes( idx, status, sizeof( uint32_t ), eibcon[loop].ipSource );
        }
    }
    logDebug( THIS_MODULE, "Server status: %s", hexdump( THIS_MODULE, status +2, STATUS_SERVER_BASE_LENGTH + connectedClients * STATUS_SERVER_CLIENT_LENGTH ));
    
    return( status );
}

/*
 * EIBnetServer thread
 * 
 * setup udp receiver for eibnet/ip packets
 * for each packet, call server handler which calls selected functions
 * 
 */
void *EIBnetServer( void *arg )
{
    struct sockaddr_in      server, client;
    struct sockaddr_in      *ipaddr;
    struct ip_mreq          mcfg;
    struct ifconf           *ifnetconfig;
    struct ifreq            *ifconfig;
    pth_attr_t              thread_attr;
    sigset_t                signal_set;
    unsigned char           *buf;
    int                     addrlen;
    int                     len;
    int                     tmp;
    char                    *dump;
    char                    ip_text[BUFSIZE_IPADDR];
    sSecurityAddr           *p_secAddr;
    eSecAddrType            secType;
    
    logInfo( THIS_MODULE, msgStartupEIBnetServer );

    /* block signals */
    pth_sigmask( SIG_SETMASK, NULL, &signal_set);
    sigaddset( &signal_set, SIGUSR1 );
    sigaddset( &signal_set, SIGUSR2 );
    sigaddset( &signal_set, SIGINT );
    sigaddset( &signal_set, SIGPIPE );
    pth_sigmask( SIG_SETMASK, &signal_set, NULL );
    
    /*
     * initialize connection table
     */
    for( tmp = 1; tmp <= EIBNETIP_MAXCONNECTIONS; tmp++ ) {
        eibNetClearConnection( &eibcon[tmp] );
    }
    buf = NULL;
    
    /*
     * register shutdown callback handler to clean up
     */
    tid_receiver = pth_self();
    callbacks[shutdownEIBnetServer].func = serverShutdown;
    callbacks[shutdownEIBnetServer].flag = 1;

    /*
     * start forwarder thread
     */
    thread_attr = pth_attr_new();
    pth_attr_set( thread_attr, PTH_ATTR_JOINABLE, FALSE );
    pth_attr_set( thread_attr, PTH_ATTR_NAME, "EIBnetServerForward" );
    if( (tid_fwdserver = pth_spawn( thread_attr, EIBnetServerForward, NULL )) == NULL ) {
        logFatal( THIS_MODULE, msgInitThread );
        Shutdown();
    }
    
    // open socket to receive EIBnet/IP packets on
    bzero( (void *)&server, sizeof( server ));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = config.eib_ip;
    server.sin_port = htons( config.eib_port );
    
    sock_eibserver = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
    
    tmp = 1;
    if( setsockopt( sock_eibserver, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof( tmp )) < 0 ) {
        logDebug( THIS_MODULE, "Unable to set address reusable: %d - %s", errno, strerror( errno ));
    }
    
    // on all network interfaces connected to system (except lo)
    // enable multicast receiption on EIBnet/IP port
    ifnetconfig = allocMemory( THIS_MODULE, sizeof( struct ifconf ));
    buf = allocMemory( THIS_MODULE, BUFSIZ );
    ifnetconfig->ifc_len = BUFSIZ;
    ifnetconfig->ifc_buf = (char *)buf;
    if( ioctl( sock_eibserver, SIOCGIFCONF, ifnetconfig ) != 0 || ifnetconfig->ifc_len == BUFSIZ ) {
        logError( THIS_MODULE, msgEIBnetNoMCast, errno, strerror( errno ));
    } else {
        ifconfig = ifnetconfig->ifc_req;
        for( tmp = ifnetconfig->ifc_len / sizeof( struct ifreq ); --tmp >= 0; ifconfig++ ) {
            if( strcmp( ifconfig->ifr_name, "lo" ) == 0 ) {
                // skip interface 'lo' - we are not expecting multicast requests on it
                continue;
            }
            ipaddr = (struct sockaddr_in *) &ifconfig->ifr_addr;
            if( ipaddr->sin_addr.s_addr != config.eib_ip ) {
                // skip interface - address not defined as listener
                continue;
            }
            mcfg.imr_multiaddr.s_addr = inet_addr( EIBNETIP_MULTICAST_ADDRESS );
            mcfg.imr_interface.s_addr = ipaddr->sin_addr.s_addr;
            logDebug( THIS_MODULE, "Activating multicast receiption on %s", ip_addr( mcfg.imr_interface.s_addr, ip_text ));
            if( setsockopt( sock_eibserver, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcfg, sizeof( mcfg )) < 0 && errno != EADDRINUSE ) {
                // if system has more than one IP address on same subnet, setsockopt() will fail
                // with "address already in use" - it still works, though, and instead of
                // doing some complicated stuff to detect such situations, simply ignore this error
                logError( THIS_MODULE, msgEIBnetNoMCast, errno, strerror( errno ));
            }
        }
    }
    free( buf );
    free( ifnetconfig );
    buf = NULL;     // important!!!
    
    if( sock_eibserver < 0 || bind( sock_eibserver, (struct sockaddr*)&server, sizeof( server )) == -1 ) {
        logCritical( THIS_MODULE, msgEIBnetSocket, errno );
        serverShutdown();
    }
    
    addrlen = sizeof( client );
    while( true ) {
        pth_yield( NULL );
        
        // the request buffer - will be freed by EIBnetTunnelForward
        if( buf == NULL ) {
            buf = allocMemory( THIS_MODULE, EIBNETIP_FRAME_SIZE );                     // too big ??? !!!
        }
        bzero( (void *)&client, sizeof( client ));

        while( true ) {
            pth_yield( NULL );
            len = pth_recvfrom( sock_eibserver, (void*)buf, EIBNETIP_FRAME_SIZE, MSG_DONTWAIT, (struct sockaddr*)&client, (socklen_t *)&addrlen );
            if( len >= EIBNETIP_FRAME_SIZE ) {
                logDebug( THIS_MODULE, "Maximum frame size matched or exceeded (%d bytes)", len );
            }
            if( len == -1 && errno == EAGAIN ) {
                continue;
            } else if( len > 0 ) {
                break;
            }
        }
        
        /*
         * security check
         */
        if( config.secEIBnetip != NULL ) {
            for( p_secAddr = config.secEIBnetip; p_secAddr != NULL; p_secAddr = p_secAddr->next ) {
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
                    continue;
                } else {
                    logDebug( THIS_MODULE, "Request from %s:%d allowed due to rule %d", ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), p_secAddr->rule );
                }
            }
        } else {
        	p_secAddr = NULL;
        }
        
        dump = hexdump( EIBNETIP_SERVER, buf, len );
        logTraceServer( EIBNETIP_SERVER, msgFrameReceived, ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), dump );
        free( dump );
        statsTotalReceived++;
        if( len >= 0 ) {
            secType = (p_secAddr != NULL) ? p_secAddr->type : config.defaultAuthEIBnet;
            if( secType > config.maxAuthEIBnet ) {
                secType = config.maxAuthEIBnet;
            }
            if( (tmp = EIBnetIPProtocolHandler( EIBNETIP_SERVER, buf, len, secType )) != 0 ) {
            	if( tmp == -2 ) {
                    logVerbose( THIS_MODULE, msgSecurityBlock, ip_addr( client.sin_addr.s_addr, ip_text ), ntohs( client.sin_port ), (p_secAddr != NULL) ? p_secAddr->rule : -1 );
            	}  else if( tmp > 0 ) {
	                // request has not finished completely
	                // allocate new buffer
	                // old one will/must be freed by other code (e.g. eibTunnelForward)
	                buf = NULL;
            	} else {
            		// maybe should abort connection here
            	}
            }
        }
    }
    
    return( NULL );     // will never get here, but required to make PPC compiler happy
}
