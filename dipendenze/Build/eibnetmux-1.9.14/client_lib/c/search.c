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
 *   \brief Search for eibnetmux servers
 * \endif
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <pth.h>

#include "../../eibnetmux/include/eibnetip.h"
#include "enmx_lib.private.h"

/*
 * local functions
 */
static sENMX_Server *   _getservers( int mode, int seconds );
static int              _getsourceaddress( int mode, const uint32_t ip_dest, uint32_t *ip_src );


/*!
 * \addtogroup xgSetup
 * @{
 */

/*!
 * \brief return list of eibnetmux servers
 * 
 * The client sends an EIBnet/IP search request to the standard EIBnet/IP multicast IP address.
 * Active servers reply by sending their server information.
 * 
 * The function constructs a linked list of all replying servers with all eibnetmux servers
 * at the head of the list.
 * 
 * An eibnetmux server is only found if its EIBnet/IP server is active (-s given on command line) 
 * 
 * \param   seconds         number of seconds to wait for servers to answer
 * 
 * \return                  server list or NULL upon error
 */
sENMX_Server *enmx_getservers( int seconds )
{
    return( _getservers( ENMX_MODE_STANDARD, seconds ));
}

/*!
 * \brief return list of eibnetmux servers (PTH mode)
 * 
 * The client sends an EIBnet/IP search request to the standard EIBnet/IP multicast IP address.
 * Active servers reply by sending their server information.
 * 
 * The function constructs a linked list of all replying servers with all eibnetmux servers
 * at the head of the list.
 * 
 * An eibnetmux server is only found if its EIBnet/IP server is active (-s given on command line)
 * 
 * This function uses PTH calls to cooperate in a non-preemptive thread environment. 
 * 
 * \param   seconds         number of seconds to wait for servers to answer
 * 
 * \return                  server list or NULL upon error
 */
sENMX_Server *enmx_pth_getservers( int seconds )
{
    return( _getservers( ENMX_MODE_PTH, seconds ));
}


/*!
 * \brief release memory allocated for list of eibnetmux servers
 * 
 * \param   list            list of servers
 * 
 * \return                  -
 */
void enmx_releaseservers( sENMX_Server *list )
{
    sENMX_Server    *temp;
    
    while( list != NULL ) {
        temp = list;
        list = list->next;
        if( temp->version != NULL ) free( temp->version );
        if( temp->hostname != NULL ) free( temp->hostname );
        free( temp );
    }
}


/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief internal function to return list of eibnetmux servers
 * 
 * This is the worker function used by both the standard and PTH version
 * of getservers().
 * 
 * \param   seconds         number of seconds to wait for servers to answer
 * 
 * \return                  server list or NULL upon error
 */
static sENMX_Server *_getservers( int mode, int seconds )
{
    pth_event_t             ev_wakeup;
    int                     sock;
    struct sockaddr_in      server, client, me;
    struct protoent         *proto_entry;
    struct hostent          *h;
    EIBNETIP_SEARCH_REQUEST request;
    sigset_t                signal_org;
    sigset_t                signal_new;
    uint32_t                my_ip;
    int                     addrlen;
    int                     len;
    unsigned char           buf[128];
    time_t                  endtime;
    sENMX_Server            *list_eibnetmux = NULL;
    sENMX_Server            *list_others = NULL;
    sENMX_Server            *entry;
    
    // library initialised?
    if( enmx_mode != ENMX_LIB_INITIALISED ) {
        return( NULL );
    }
    
    // create socket to send request on
    bzero( (void *)&client, sizeof( struct sockaddr_in ));
    client.sin_family = AF_INET;
    client.sin_addr.s_addr = htonl( INADDR_ANY );
    client.sin_port = htons( 0 );
    
    proto_entry = getprotobyname( "udp" );
    sock = socket( PF_INET, SOCK_DGRAM, proto_entry->p_proto );
    if( sock < 0 || bind( sock, (struct sockaddr *)&client, sizeof( struct sockaddr_in )) == -1 ) {
        return( NULL );
    }
    
    // create target socket
    bzero( (void *)&server, sizeof( server ));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr( EIBNETIP_MULTICAST_ADDRESS );
    server.sin_port = htons( EIBNETIP_PORT_NUMBER );
    
    // get my ip address
    len = sizeof( me );
    if( getsockname( sock, (struct sockaddr *)&me, (socklen_t *)&len ) != 0 ) {
        return( NULL );
    }
    if( _getsourceaddress( mode, server.sin_addr.s_addr, &my_ip ) != 0 ) {
        return( NULL );
    }
    
    // create search request
    request.headersize = HEADER_SIZE_10;
    request.version = EIBNETIP_VERSION_10;
    request.servicetype = htons( SEARCH_REQUEST );
    request.totalsize = htons( sizeof( EIBNETIP_SEARCH_REQUEST ));
    request.structlength = (unsigned char)(sizeof( EIBNETIP_HPAI ) & 0xff);
    request.hostprotocol = IPV4_UDP;
    request.ip = my_ip;
    request.port = me.sin_port;
    
    /* block signals */
    if( mode == ENMX_MODE_STANDARD ) {
        sigprocmask( 0, NULL, &signal_org);
        memcpy( &signal_new, &signal_org, sizeof( sigset_t ));
        sigaddset( &signal_new, SIGUSR1 );
        sigaddset( &signal_new, SIGUSR2 );
        sigaddset( &signal_new, SIGINT );
        sigaddset( &signal_new, SIGPIPE );
        sigprocmask( SIG_BLOCK, &signal_new, NULL );
    } else {
        pth_sigmask( 0, NULL, &signal_org);
        memcpy( &signal_new, &signal_org, sizeof( sigset_t ));
        sigaddset( &signal_new, SIGUSR1 );
        sigaddset( &signal_new, SIGUSR2 );
        sigaddset( &signal_new, SIGINT );
        sigaddset( &signal_new, SIGPIPE );
        pth_sigmask( SIG_BLOCK, &signal_new, NULL );
    }
    
    // send multicast search request
    if( mode == ENMX_MODE_STANDARD ) {
        (void) sendto( sock, (void *)&request, sizeof( EIBNETIP_SEARCH_REQUEST ), 0, (struct sockaddr *)&server, sizeof( struct sockaddr_in ) );
    } else {
        (void) pth_sendto( sock, (void *)&request, sizeof( EIBNETIP_SEARCH_REQUEST ), 0, (struct sockaddr *)&server, sizeof( struct sockaddr_in ) );
    }
    
    // receive answers from EIBnet/IP servers
    // this list will include eibnetmux servers and others
    addrlen = sizeof( server );
    endtime = time( NULL ) + seconds;
    if( mode == ENMX_MODE_STANDARD ) {
        while( 1 ) {
            bzero( (void *)&server, sizeof( server ));
            len = recvfrom( sock, (void*)buf, 128, MSG_DONTWAIT, (struct sockaddr*)&server, (socklen_t *)&addrlen );
            if( len == -1 && errno == EAGAIN ) {
                if( time( NULL ) <= endtime ) {
                    continue;
                }
                break;
            }
            entry = malloc( sizeof( sENMX_Server ));
            entry->ip = server.sin_addr.s_addr;
            entry->port = server.sin_port;
            entry->version = strdup( (char *)&buf[ sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_HPAI ) + 24 ] );
            h = gethostbyaddr( &server.sin_addr, sizeof( server.sin_addr ), AF_INET );
            if( h != NULL ) {
                entry->hostname = strdup( h->h_name );
            } else {
                entry->hostname = NULL;
            }
            if( strncasecmp( entry->version, "eibnetmux", 9 ) == 0 ) {
                entry->eibnetmux = 1;
                entry->next = list_eibnetmux;
                list_eibnetmux = entry;
            } else {
                entry->eibnetmux = 0;
                entry->next = list_others;
                list_others = entry;
            }
        }
    } else {
        while( 1 ) {
            if( time( NULL ) > endtime ) {
                break;
            }
            bzero( (void *)&server, sizeof( server ));
            ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( endtime, 0 ));
            len = pth_recvfrom_ev( sock, (void*)buf, 128, 0, (struct sockaddr*)&server, (socklen_t *)&addrlen, ev_wakeup );
            if( pth_event_status( ev_wakeup ) != PTH_STATUS_OCCURRED ) {
                // not timeout but response received
                entry = malloc( sizeof( sENMX_Server ));
                entry->ip = server.sin_addr.s_addr;
                entry->port = server.sin_port;
                entry->version = strdup( (char *)&buf[ sizeof( EIBNETIP_HEADER ) + sizeof( EIBNETIP_HPAI ) + 24 ] );
                h = gethostbyaddr( &server.sin_addr, sizeof( server.sin_addr ), AF_INET );
                if( h != NULL ) {
                    entry->hostname = strdup( h->h_name );
                } else {
                    entry->hostname = NULL;
                }
                if( strncasecmp( entry->version, "eibnetmux", 9 ) == 0 ) {
                    entry->eibnetmux = 1;
                    entry->next = list_eibnetmux;
                    list_eibnetmux = entry;
                } else {
                    entry->eibnetmux = 0;
                    entry->next = list_others;
                    list_others = entry;
                }
            }
            pth_event_free( ev_wakeup, PTH_FREE_ALL );
            continue;
        }
    }
    
    // append list of other servers to eibnetmux list 
    if( list_eibnetmux != NULL ) {
        for( entry = list_eibnetmux; entry->next != NULL; entry = entry->next ) {
            ;
        }
        entry->next = list_others;
    } else {
        list_eibnetmux = list_others;
    }
    
    // restore signals
    if( mode == ENMX_MODE_STANDARD ) {
        sigprocmask( SIG_SETMASK, &signal_org, NULL );
    } else {
        pth_sigmask( SIG_SETMASK, &signal_org, NULL );
    }
    
    return( list_eibnetmux );
}


#ifdef HAVE_LINUX_RTNETLINK
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*!
 * \brief structure to retrieve routing information from kernel
 */
typedef struct
{
    struct nlmsghdr     n;
    struct rtmsg        r;
    char                data[1000];
} r_req;
#endif

/*!
 * \brief get our own IP address
 * 
 * If the system supports the netlink/rtnetlink interface (indicated by HAVE_LINUX_RTNETLINK)
 * the source IP address is determined by querying the kernel's routing information.
 * This is the case on any sufficiently recent Linux kernel.
 * 
 * Otherwise, a simple system is assumed which has only one interface. In addition,
 * DNS must be configured correctly to return the external network interface's
 * IP address (not localhost). This is not very safe but such a situation is probably
 * also very rare - unless eibnetmux is ported to a different operating system
 * environment. But then, many things need to be adapted.
 * 
 * \param       dest                    address of target to send request to
 * \param       source                  buffer to receive corresponding source address
 * 
 * \return                              0: ok, -1: error
 */
static int _getsourceaddress( int mode, const uint32_t ip_dest, uint32_t *ip_src )
{
#ifdef HAVE_LINUX_RTNETLINK
    int             ksock;
    int             len;
    r_req           req;
    struct rtattr   *attributes;
    
    memset( &req, 0, sizeof( req ));
    memset( ip_src, 0, sizeof( *ip_src ));
    
    // open netlink socket to kernel to retrieve IP & routing information
    ksock = socket( PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );
    if( ksock == -1 ) {
        return( -1 );
    }
    
    // setup to retrieve routing information
    req.n.nlmsg_len = NLMSG_SPACE( sizeof( req.r )) + RTA_LENGTH( sizeof( ip_dest ));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_type = RTM_GETROUTE;
    req.r.rtm_family = AF_INET;
    req.r.rtm_dst_len = 32;
    
    // get routing information on how to get to destination address
    attributes = (struct rtattr *) ((char *) &req + NLMSG_SPACE( sizeof( req.r )));
    attributes->rta_type = RTA_DST;
    attributes->rta_len = RTA_LENGTH( sizeof( ip_dest ));
    memcpy( RTA_DATA( attributes ), &ip_dest, sizeof( ip_dest ));
    if( mode == ENMX_MODE_STANDARD ) {
        if( write( ksock, &req, req.n.nlmsg_len ) < 0 ) {
            return( -1 );
        }
        if( read( ksock, &req, sizeof( req )) < 0 ) {
            return( -1 );
        }
    } else {
        if( pth_write( ksock, &req, req.n.nlmsg_len ) < 0 ) {
            return( -1 );
        }
        if( pth_read( ksock, &req, sizeof( req )) < 0 ) {
            return( -1 );
        }
    }
    close( ksock );
    if( req.n.nlmsg_type == NLMSG_ERROR ) {
        return( -1 );
    }
    
    // extract routing information
    len = ( (struct nlmsghdr *) &req)->nlmsg_len;
    while( RTA_OK( attributes, len )) {
        if( attributes->rta_type == RTA_PREFSRC && RTA_PAYLOAD( attributes ) == sizeof( ip_src )) {
            // this is the preferred route and the address 'type' matches (well, they have the same size ...)
            memcpy( ip_src, RTA_DATA( attributes ), RTA_PAYLOAD( attributes ));
            return( 0 );
        }
        attributes = RTA_NEXT( attributes, len );
    }
    return( -1 );
#else
    struct hostent  *h;
    char            *name;
    u_long          *ptr;

    name = malloc( 128 );
    if( gethostname( name, 128 ) != 0 )
        return( -1 );

    h = gethostbyname( name );
    if( !h ) {
        return( -1 );
    }

    ptr = (u_long *)(h->h_addr_list[0]);
    *ip_src = *ptr;

    return( 0 );
#endif
}
/*!
 * \endcond
 */
/*! @} */
