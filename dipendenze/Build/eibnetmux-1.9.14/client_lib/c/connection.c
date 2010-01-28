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
 *   \brief Connection management
 * \endif
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <pth.h>

#include "enmx_lib.private.h"


/*!
 * \addtogroup xgSetup
 * @{
 */

/*
 * local function declarations
 */
static ENMX_HANDLE  _enmx_open( int mode, char *hostname, char *myname );


/*!
 * \brief close connection with eibnetmux socket server
 * 
 * \param   conn            connection handle as returned by enmx_open()
 */
void enmx_close( ENMX_HANDLE conn )
{
    sConnectionInfo         **connInfo, *temp;
    SOCKET_CMD_HEAD         cmd_head;
    pth_event_t             ev_wakeup;
    time_t                  secs;
    
    temp = NULL;
    for( connInfo = &enmx_connections; *connInfo != NULL; connInfo = &(*connInfo)->next ) {
        if( (*connInfo)->socket == conn ) {
            temp = *connInfo;
            *connInfo = (*connInfo)->next;
            break;
        }
    }
    
    if( temp != NULL ) {
        cmd_head.cmd = SOCKET_CMD_EXIT;
        cmd_head.address = 0xffff;
        secs = time( NULL ) + TIMEOUT;
        switch( temp->mode ) {
            case ENMX_MODE_STANDARD:
                while( write( conn, &cmd_head, sizeof( cmd_head )) == -1 ) {
                    if( errno == EAGAIN ) {
                        if( secs <= time( NULL )) {
                            break;
                        }
                        usleep( 10 * 1000 );
                        continue;
                    }
                }
                break;
            case ENMX_MODE_PTH:
                ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
                pth_write_ev( conn, &cmd_head, sizeof( cmd_head ), ev_wakeup );
                // either the request has been sent or timeout reached
                // in any case, we've finished
                pth_event_free( ev_wakeup, PTH_FREE_ALL );
                break;
        }
        if( temp->hostname ) free( temp->hostname );
        if( temp->name ) free( temp->name );
        free( temp );
    }

    close( conn );
}


/*!
 * \brief establish connection with eibnetmux socket server
 * 
 * \param   hostname        name or ip address and port of eibnetmux server, format hostname:port
 * \param   clientid        user selectable identification of client
 * 
 * \return                  handle, <0: error
 * 
 * error codes:
 *      -1              resource problems
 *      -2              unknown server name
 *      -3              unable to establish connection (server not running, etc.)
 */
ENMX_HANDLE enmx_open( char *hostname, char *clientid )
{
    return( _enmx_open( ENMX_MODE_STANDARD, hostname, clientid ));
}

/*!
 * \brief connection with eibnetmux socket server (PTH version)
 * 
 * \param   hostname        name or ip address and port of eibnetmux server, format hostname:port
 * \param   clientid        user selectable identification of client
 * 
 * \return                  handle, <0: error
 * 
 * error codes:
 *      -1              resource problems
 *      -2              unknown server name
 *      -3              unable to establish connection (server not running, etc.)
 */
ENMX_HANDLE enmx_pth_open( char *hostname, char *clientid )
{
    return( _enmx_open( ENMX_MODE_PTH, hostname, clientid ));
}


/*!
 * \brief retrieve hostname of connected eibnetmux server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  name or ip address and port of eibnetmux server, format hostname:port
 */
char *enmx_gethost( ENMX_HANDLE handle )
{
    sConnectionInfo         *connInfo;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( NULL );
    }
    
    return( connInfo->hostname );
}


/*!
 * \if DeveloperDocs
 * \brief internal worker function to establishes connection with eibnetmux socket server
 * 
 * \param   hostname        name or ip address and port of eibnetmux server, format hostname:port
 * \param   clientid        user selectable identification of client
 * 
 * \return                  handle, <0: error
 * 
 * error codes:
 *      -1              resource problems
 *      -2              unknown server name
 *      -3              unable to establish connection (server not running, etc.)
 * \endif
 */
static ENMX_HANDLE _enmx_open( int mode, char *hostname, char *myname )
{
    sConnectionInfo         *connInfo;
    sENMX_Server            *server_list;
    sENMX_Server            *server_entry;
    int                     sock_con;
    struct sockaddr_in      server, client;
    struct protoent         *proto_entry;
    struct hostent          *h;
    uint32_t                *addr;
    uint32_t                target_address;
    char                    *target_name = NULL;    // stupid, but keeps compiler happy
    char                    *ptr;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // library initialised?
    if( enmx_mode != ENMX_LIB_INITIALISED ) {
        return( ENMX_E_NOT_INITIALISED );
    }
    
    // client name must be specified
    if( myname == NULL || strlen( myname ) == 0 ) {
        return( ENMX_E_NOCLIENTID );
    }
    
    // get host's ip address
    //   if no hostname specified, search for eibnetmux servers
    //   if exactly one is found, use it, otherwise return with error
    ptr = NULL;
    if( hostname != NULL ) {
        ptr = strchr( hostname, ':' );
        if( ptr != NULL ) {
            *ptr++ = '\0';
        }
        
        h = gethostbyname( hostname );
        if( !h ) {
            return( ENMX_E_HOST_NOTFOUND );
        }
        
        addr = (uint32_t *)(h->h_addr_list[0]);
        target_address = *addr;
        target_name = strdup( hostname );
    } else {
        target_address = 0;
        server_list = enmx_getservers( 1 );
        for( server_entry = server_list; server_entry != NULL; server_entry = server_entry->next ) {
            if( server_entry->eibnetmux == 1 ) {
                if( target_address != 0 ) {
                    return( ENMX_E_SEARCH );
                }
                target_address = server_entry->ip;
                target_name = strdup( server_entry->hostname );
            } else {
                // all eibnetmux server are first in the list
                break;
            }
        }
        if( target_address == 0 ) {
            return( ENMX_E_SEARCH );
        }
    }
    
    // establish connection with eibnetmux
    proto_entry = getprotobyname( "tcp" );
    sock_con = socket( PF_INET, SOCK_STREAM, proto_entry->p_proto );
    if( sock_con < 0 ) {
        return( ENMX_E_RESOURCE );
    }
    bzero( (void *)&client, sizeof( client ));
    client.sin_family = AF_INET;
    client.sin_addr.s_addr = INADDR_ANY;
    client.sin_port = htons( 0 );
    if( bind( sock_con, (struct sockaddr *)&client, sizeof(struct sockaddr_in) ) == -1 ) {
        close( sock_con );
        return( ENMX_E_RESOURCE );
    }
    bzero( (void *)&server, sizeof( server ));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = target_address;
    if( ptr != NULL ) {
        server.sin_port = htons( atoi( ptr ));
    } else {
        server.sin_port = htons( SOCKET_TCP_PORT );
    }
    
    switch( mode ) {
        case ENMX_MODE_STANDARD:
            if( connect( sock_con, (struct sockaddr *)&server, sizeof( struct sockaddr_in )) != 0 ) {
                close( sock_con );
                return( ENMX_E_SERVER_NOTRUNNING );
            }
            break;
        case ENMX_MODE_PTH:
            if( pth_connect( sock_con, (struct sockaddr *)&server, sizeof( struct sockaddr_in )) != 0 ) {
                close( sock_con );
                return( ENMX_E_SERVER_NOTRUNNING );
            }
            break;
    }
    
    // sanitize name
    if( strlen( myname ) >= SOCKET_NAME_MAX_LENGTH ) {
        myname[SOCKET_NAME_MAX_LENGTH] = '\0';
    }
    
    /*
     * update connection info
     */
    connInfo = malloc( sizeof( sConnectionInfo ));
    connInfo->socket    = sock_con;
    connInfo->errorcode = 0;
    connInfo->next      = enmx_connections;
    connInfo->state     = stateUnused;
    connInfo->hostname  = target_name;      // strdup'ed above
    connInfo->name      = strdup( myname );
    connInfo->mode      = mode;
    connInfo->L7connection = 0;
    connInfo->L7sequence_id = 0;
    switch( mode ) {
        case ENMX_MODE_STANDARD:
            connInfo->send = _enmx_send;
            connInfo->recv = _enmx_receive;
            connInfo->wait = _enmx_wait;
            break;
        case ENMX_MODE_PTH:
            connInfo->send = _enmx_pth_send;
            connInfo->recv = _enmx_pth_receive;
            connInfo->wait = _enmx_pth_wait;
    }
    enmx_connections    = connInfo;
    
    // register clientid
    cmd_head.cmd = SOCKET_CMD_NAME;
    cmd_head.address = htons( strlen( myname ));
    ecode = connInfo->send( sock_con, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        enmx_close( sock_con );
        return( ENMX_E_REGISTER_CLIENT );
    }
    
    // append name
    ecode = connInfo->send( sock_con, (unsigned char *)myname, strlen( myname ));
    if( ecode < 0 ) {
        enmx_close( sock_con );
        return( ENMX_E_REGISTER_CLIENT );
    }
    
    // get acknowledgement
    ecode = connInfo->recv( sock_con, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        enmx_close( sock_con );
        return( ENMX_E_REGISTER_CLIENT );
    }
    if( rsp_head.status != SOCKET_STAT_NAME ) {
        enmx_close( sock_con );
        return( ENMX_E_REGISTER_CLIENT );
    }
    
    return( sock_con );
}
/*! @} */
