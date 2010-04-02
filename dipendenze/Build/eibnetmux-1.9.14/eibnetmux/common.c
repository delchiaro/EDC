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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"
#include "include/eibnetip_private.h"


/*
 * local functions
 */
static int      eibNetIpSendWithWait( void *system, EIBNETIP_CONNECTION *conn, int sock, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size );


/**
 * extract cemi data from eibnet/ip receive buffer, beginning at actual start of cemi part
 **/
void eibCemiExtract( CEMI_L_DATA_MESSAGE *cemi, uint8_t *rcvdata )
{
    cemi->mc = rcvdata[0];
    
    if( cemi->mc == L_DATA_REQ || cemi->mc == L_DATA_CON || cemi->mc == L_DATA_IND ) {
        cemi->addil = rcvdata[1];
        if( cemi->addil > 0 ) {
            cemi->addi = &rcvdata[2];
        }
        cemi->ctrl1   = rcvdata[2+ cemi->addil];
        cemi->ctrl2   = rcvdata[2+ cemi->addil +1];
        cemi->saddr   = (uint16_t)rcvdata[2+ cemi->addil +2];
        cemi->daddr   = (uint16_t)rcvdata[2+ cemi->addil +4];
        cemi->datal   = rcvdata[2+ cemi->addil +6];
        cemi->data    = &rcvdata[2+ cemi->addil +8]; // siemens ip router sends 00 before actual data
    }
}


/*
 * clear entry in connection table
 */
void eibNetClearConnection( EIBNETIP_CONNECTION *conn )
{
    if( conn == NULL ) {
        return;
    }
    
    conn->connectionid         = 0;
    conn->channelid            = 0;
    conn->sequencecounter_rcv  = 0;
    conn->sequencecounter_sent = 0;
    conn->connectiontype       = 0;
    conn->connectioninfo       = 0;
    conn->lastHeartBeat        = 0;
    conn->status               = E_NO_ERROR;
    conn->knxaddress           = 0;
    memset( &conn->hpai, 0, sizeof( EIBNETIP_HPAI ));
    conn->loopback             = loopbackUndefined;
    conn->nextsend             = 0;
    conn->counter              = 0;
    conn->threadid             = 0;
    if( conn->mtxResponse  != 0 ) free( conn->mtxResponse );
    if( conn->condResponse != 0 ) free( conn->condResponse );
    conn->mtxResponse          = NULL;
    conn->condResponse         = NULL;
}


/*
 * setupSignalling
 * 
 * initialize mutex & condition variable to enable signalling receiption of acknowledgement
 */
void setupSignalling( void *module, uint8_t channelid )
{
    eibcon[channelid].mtxResponse  = allocMemory( module, sizeof( pth_mutex_t ));
    eibcon[channelid].condResponse = allocMemory( module, sizeof( pth_cond_t ));
    
    pth_mutex_init( eibcon[channelid].mtxResponse );
    pth_cond_init( eibcon[channelid].condResponse );
}


/*
 * releaseSignalling
 * 
 * release memory allocated for signalling
 */
void releaseSignalling( uint8_t channelid )
{
    if( eibcon[channelid].mtxResponse != NULL ) free( eibcon[channelid].mtxResponse );
    if( eibcon[channelid].condResponse != NULL ) free( eibcon[channelid].condResponse );

    eibcon[channelid].mtxResponse = NULL;
    eibcon[channelid].condResponse = NULL;
}


/*
 * eibNetIpSendControl
 * 
 * send eibnet/ip frame over control connection
 */
int eibNetIpSendControl( void *system, EIBNETIP_CONNECTION *conn, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size )
{
    if( conn != NULL ) {
        logDebug( system, "send request: conn=%08x, mutex=%08x, cond=%08x", conn, conn->mtxResponse, conn->condResponse );
    }
    if( conn == NULL || conn->mtxResponse == NULL || conn->condResponse == NULL ) {
        eibNetIpSend( system, (system == EIBNETIP_SERVER) ? sock_eibserver : sock_eibclient_control, receiver, service_type, senddata, data_size );
        return( 0 );
    } else {
        return( eibNetIpSendWithWait( system, conn, (system == EIBNETIP_SERVER) ? sock_eibserver : sock_eibclient_control, receiver, service_type, senddata, data_size ));
    }
}


/*
 * eibNetIpSendData
 * 
 * send eibnet/ip frame over data connection (usually tunneling frames)
 */
int eibNetIpSendData( void *system, EIBNETIP_CONNECTION *conn, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size )
{
    if( conn == NULL || conn->mtxResponse == NULL || conn->condResponse == NULL ) {
        eibNetIpSend( system, (system == EIBNETIP_SERVER) ? sock_eibserver : sock_eibclient_data, receiver, service_type, senddata, data_size );
        return( 0 );
    } else {
        return( eibNetIpSendWithWait( system, conn, (system == EIBNETIP_SERVER) ? sock_eibserver : sock_eibclient_data, receiver, service_type, senddata, data_size ));
    }
}


/*
 * eibNetIpSend
 * 
 * sends EIBnet/IP packet to client or server
 * first adds appropriate header
 *
 * sends *senddata of length data_size (without eibnetip header size!!) with service type
 * service_type to endpoint receiver
 * according to protocol stated in HPAI either tcp or udp is used
 **/
void eibNetIpSend( void *module, int sock, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size )
{
    EIBNETIP_PACKET         *p;
    socklen_t               dest_len;
    struct sockaddr_in      dest;
    uint16_t                len;
    char                    *dump;
    char                    ip_text[BUFSIZE_IPADDR];
    
    // prepare EIBNET/IP packet
    len = HEADER_SIZE_10 + data_size;
    p = allocMemory( module, len );
    p->head.headersize  = HEADER_SIZE_10;
    p->head.version     = EIBNETIP_VERSION_10;
    p->head.servicetype = htons( service_type );
    p->head.totalsize   = htons( len );
    if( senddata != NULL && data_size > 0 ) {
        memcpy( &p->data, senddata, data_size );
    }

    switch( receiver->hostprotocol ) {
        case IPV4_UDP:
            // send UDP packet
            // UDPSendData( ( uint8_t *) &p, p.head.totalsize, &udph, &iph );
            bzero( (void *)&dest, sizeof( dest ));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = receiver->ip;
            dest.sin_port = receiver->port;
            dest_len = sizeof( dest );
            pth_sendto( sock, (void *)p, len, 0, (struct sockaddr *)&dest, dest_len );
            // log
            dump = hexdump( module, p, len );
            if( module == EIBNETIP_CLIENT ) {
                    logTraceClient( module, msgFrameSent, ip_addr( receiver->ip, ip_text ), ntohs( receiver->port ), dump );
            } else if( module == EIBNETIP_SERVER ) {
                    logTraceServer( module, msgFrameSent, ip_addr( receiver->ip, ip_text ), ntohs( receiver->port ), dump );
            }
            free( dump );
            break;
        case IPV4_TCP:
            logDebug( module, "TCP currently not supported..." );
            break;
        default:
            logDebug( module, "Unsupported hostprotocol:0x%02x", receiver->hostprotocol );
            break;  
    }
    free( p );
}


/*
 * eibNetIpSendWithWait
 * 
 * send request and wait for response
 */
static int eibNetIpSendWithWait( void *system, EIBNETIP_CONNECTION *conn, int sock, EIBNETIP_HPAI *receiver, uint16_t service_type, uint8_t *senddata, uint16_t data_size )
{
    pth_event_t             ev_wakeup;
    time_t                  secs;
    uint8_t                 retries;
    
    for( retries = 0; retries < 3; retries++ ) {
        secs = time( NULL ) + ACKNOWLEDGEMENT_TIMEOUT;
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
        // secs = ACKNOWLEDGEMENT_TIMEOUT;
        // ev_wakeup = pth_event( PTH_EVENT_TIME, pth_timeout( secs, 0 ));
        pth_mutex_acquire( conn->mtxResponse, FALSE, NULL );

        eibNetIpSend( system, sock, receiver, service_type, senddata, data_size );

        pth_cond_await( conn->condResponse, conn->mtxResponse, ev_wakeup );
        pth_mutex_release( conn->mtxResponse );
        
        if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
            // ack received
            return( 0 );
        }
    }
                    
    return( -1 );
}


/*!
 * \brief remove first element of queue and release associated memory
 * 
 * \long This code assumes that only the first queue entry can ever be removed.
 * The reasoning goes like this: As all threads handle the queue entries in order,
 * the first one completed by all threads must be the first entry. Obviously,
 * at that time, other entries may already have been completed by one or the other
 * thread and marked accordingly. However, they cannot be completede unless all
 * previous entries have been completed, too, and consequently removed from the queue.
 * 
 * \param       module                  logger for log message
 * \param       queue                   pointer to first queue entry which will be removed and released
 * 
 * \return                              pointer to new first queue entry
 */
EIBNETIP_QUEUE *removeRequestFromQueue( void *module, EIBNETIP_QUEUE *queue )
{
    EIBNETIP_QUEUE  *temp;
    
    logDebug( module, "Tunneling request done - remove %d from queue: %08x (pending=%02x, others=%02x)", queue->nr, queue, queue->pending_eibnet, queue->pending_others );
    
    // the following check is only a safeguard and shouldn't be necessary
    if( queue->pending_others == 0 && queue->pending_eibnet == 0 ) {
        temp  = queue->next;
        free( queue->data );
        free( queue );
    } else {
        logCritical( module, msgInternalQueue );
        temp = queue;
    }
    return( temp );
}


void addRequestToQueue( void *module, EIBNETIP_QUEUE **top, unsigned char *buf, int len )
{
    static uint32_t request_number = 1;
    EIBNETIP_QUEUE  **queue;
    connmask_t      pending_eibnet = 0;
    uint32_t        pending_others = 0;
    char            *queue_name;
    int             loop;
    
    /*
     * requests received by the EIBnet/IP client must be distributed to all connected clients
     * requests received by any of the servers (EIBnet/IP, socket, eibd) are only forwarded
     * to the EIBnet/IP client (which doesn't need any pending flag)
     */
    if( module == EIBNETIP_CLIENT ) {
        // set all bits of pending_eibnet
        pending_eibnet--;
        // clear pending flags for in-existent eibnet/ip connections
        // connection 0 is reserved for the eibnet/ip client
        if( config.servers & SERVER_EIBNET ) {
            for( loop = EIBNETIP_MAXCONNECTIONS +1; loop < sizeof( connmask_t ) * 8; loop++ ) {
                pending_eibnet &= ~(1 << loop);
            }
            pending_eibnet &= 0xfe;
        } else {
            // eibnet/ip server not running
            // clear pending flags
            pending_eibnet = 0;
        }
        // set pending flag for other servers if they are running
        if( config.servers & (SERVER_TCP | SERVER_UNIX) ) {
            // either TCP or unix socket server is running
            pending_others |= QUEUE_PENDING_SOCKET;
        }
        if( config.servers & SERVER_EIBD ) {
            // eibd server is running
            pending_others |= QUEUE_PENDING_EIBD;
        }
    }
    
    // get last entry
    loop = 1;
    for( queue = top; *queue != NULL; queue = &(*queue)->next ) {
        loop++;
    }
    *queue = allocMemory( module, sizeof( EIBNETIP_QUEUE ));
    (*queue)->nr             = request_number++;
    (*queue)->next           = NULL;
    (*queue)->data           = buf;
    (*queue)->len            = len;
    (*queue)->pending_eibnet = pending_eibnet;
    (*queue)->pending_others = pending_others;
    
    // determine queue name
    queue_name = (*top == eibQueueServer) ? "server" : "client";
    logDebug( module, "Add tunneling request %d to %s queue: %08x, queue len = %d, pending eibnet = %08x, others = %08x", (*queue)->nr, queue_name, *queue, loop, pending_eibnet, pending_others );
}
