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
 * network related functions
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#ifdef HAVE_LINUX_RTNETLINK
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include <arpa/inet.h>

#include "eibnetmux.h"
#include "include/log.h"


// globals
uint32_t MyIpAddress;

 
int init_network( void )
{
        struct hostent  *h;
        char            *name;
        u_long          *ptr;

        if( config.ip != 0 ) {
                MyIpAddress = config.ip;
                return( 0 );
        }
        
        if( !config.hostname || strlen( config.hostname ) == 0 ) {
                name = malloc( 20 );
                if( gethostname( name, 20 ) != 0 )
                        return( -1 );
                config.hostname = name;
        }

        h = gethostbyname( config.hostname );
        if( !h ) {
                logDebug( logModuleMain, "My name not found: %s", config.hostname );
                MyIpAddress = 0;
                return( -1 );
        }

        ptr = (u_long *)(h->h_addr_list[0]);
        MyIpAddress = *ptr;

#ifndef HAVE_LINUX_RTNETLINK
        logWarning( logModuleMain, msgEIBnetSourceIPFixed, ipaddr( MyIpAddress ));
#endif

        return( 0 );
}


typedef struct
{
    struct nlmsghdr     n;
    struct rtmsg        r;
    char                data[1000];
} r_req;

/*!
 * \brief get our own IP address
 * 
 * \param       dest                    address of target to send request to
 * \param       source                  buffer to receive corresponding source address
 * 
 * \return                              0: ok, -1: error
 */
int network_getsourceaddress( const uint32_t ip_dest, uint32_t *ip_src )
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
    if( write( ksock, &req, req.n.nlmsg_len ) < 0 ) {
        return( -1 );
    }
    if( read( ksock, &req, sizeof( req )) < 0 ) {
        return( -1 );
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
    *ip_src = MyIpAddress;
    return( 0 );
#endif
}
