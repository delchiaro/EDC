/*!
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
 *   \brief Management functions
 * \endif
 */
 
/*!
 * \example eibstatus.c
 * 
 * Demonstrates usage of the EIBnetmux server status function.
 * 
 * It produces a status summary for an EIBnetmux server.
 */
/*!
 * \example search.c
 * 
 * Demonstrates usage of the EIBnetmux server search functions.
 * 
 * It produces a list of all active EIBnetmux servers.
 * 
 * This version does NOT rely on the GNU Pth threading library.
 */
/*!
 * \example pth_search.c
 * 
 * Demonstrates usage of the EIBnetmux server search functions.
 * 
 * It produces a list of all active EIBnetmux servers.
 * 
 * This version uses the GNU Pth threading library.
 */

#include "config.h"

/*!
 * \cond DeveloperDocs
 */
#define _GNU_SOURCE
/*!
 * \endcond
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"

/*
 * local functions
 */
static int              _client_connect( ENMX_HANDLE handle, int newstate );
static uint8_t          _get_byte( unsigned char **ptr );
static uint16_t         _get_word( unsigned char **ptr );
static uint32_t         _get_long( unsigned char **ptr );
static char             *_get_string( unsigned char **ptr );
static sENMX_Status     *_getStatus( sConnectionInfo *connInfo );
// static char             *_hexdump( void *string, int len, int spaces );


/*!
 * \addtogroup xgMgmt
 * @{
 */

/*!
 * \brief connect eibnet/ip client to remote server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_connect( ENMX_HANDLE handle )
{
    return( _client_connect( handle, 1 ));
}


/*!
 * \brief disconnect eibnet/ip client from remote server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_disconnect( ENMX_HANDLE handle )
{
    return( _client_connect( handle, 0 ));
}


/*!
 * \brief get current eibnetmux log level
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  >=0: log level, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_getloglevel( ENMX_HANDLE handle )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }
    
    // send request
    cmd_head.cmd = SOCKET_CMD_MGMT_GETLOG;
    cmd_head.address = 0;
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_MGMT_GETLOG ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( ntohs( rsp_head.size ));
}

/*!
 * \brief set new eibnetmux log level
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   level           new log level
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_setloglevel( ENMX_HANDLE handle, uint16_t level )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }
    
    // send request
    cmd_head.cmd = SOCKET_CMD_MGMT_SETLOG;
    cmd_head.address = htons( level );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_MGMT_SETLOG ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
}


/*!
 * \brief get current eibnetmux access block level
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  >=0: access block level, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_getaccessblock( ENMX_HANDLE handle )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }
    
    // send request
    cmd_head.cmd = SOCKET_CMD_MGMT_GETBLOCK;
    cmd_head.address = 0;
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_MGMT_GETBLOCK ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( ntohs( rsp_head.size ));
}

/*!
 * \brief set new eibnetmux access block level
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   level           new access block level
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_setaccessblock( ENMX_HANDLE handle, uint16_t level )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }
    
    // send request
    cmd_head.cmd = SOCKET_CMD_MGMT_SETBLOCK;
    cmd_head.address = htons( level );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_MGMT_SETBLOCK ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
}


/*!
 * \brief forcibly close a client session
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   session_type    1: EIBnet/IP clients, 2: socket clients
 * \param   session_id      id of session to close
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
int enmx_mgmt_close_session( ENMX_HANDLE handle, int session_type, uint32_t session_id )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }
    
    // send request
    cmd_head.cmd = SOCKET_CMD_MGMT_CLOSE;
    cmd_head.address = htons( session_type );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // append connection id
    session_id = htonl( session_id );
    ecode = connInfo->send( handle, (unsigned char *)&session_id, sizeof( session_id ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }

    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_MGMT_CLOSE ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
}


/*!
 * \brief release all memory used by status structure
 * 
 * \param   p_status        pointer to status structure to release
 */
void enmx_mgmt_releasestatus( sENMX_Status *p_status )
{
    sENMX_StatusEIB         *p_eib;
    sENMX_StatusSocket      *p_client;
    sENMX_StatusEIBD        *p_eibd;
    
    if( p_status == NULL ) {
        return;
    }
    
    while( p_status->server.clients != NULL ) {
        p_eib = p_status->server.clients;
        p_status->server.clients = p_status->server.clients->next;
        free( p_eib );
    }
    
    while( p_status->socketserver.clients != NULL ) {
        p_client = p_status->socketserver.clients;
        p_status->socketserver.clients = p_status->socketserver.clients->next;
        if( p_client->name != NULL ) free( p_client->name );
        if( p_client->user != NULL ) free( p_client->user );
        free( p_client );
    }
    
    while( p_status->eibd.clients != NULL ) {
        p_eibd = p_status->eibd.clients;
        p_status->eibd.clients = p_status->eibd.clients->next;
        free( p_eibd );
    }
    
    if( p_status->common.version != NULL ) free( p_status->common.version );
    if( p_status->client.target_name != NULL ) free( p_status->client.target_name );
    if( p_status->socketserver.path != NULL ) free( p_status->socketserver.path );
    
    free( p_status );
}


/*!
 * \brief return structure with eibnetmux status
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  
 *      status              pointer to newly allocated structure containing server status information or NULL in case of an error
 */
sENMX_Status *enmx_mgmt_getstatus( ENMX_HANDLE handle )
{
    sConnectionInfo         *connInfo;
    sENMX_Status            *status;
    
     // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( NULL );
    }
    
    status = _getStatus( connInfo );
    
    if( status != NULL ) {
        connInfo->errorcode = ENMX_E_NO_ERROR;
    }
    return( status );
}


/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief internal worker function to connect/disconnect eibnet/ip client to/from remote server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   newstate        new connection state
 * 
 * \return                  0: ok, -1: error (use geterror to retrieve error code)
 */
static int _client_connect( ENMX_HANDLE handle, int newstate )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( -1 );
    }

    // check parameter
    newstate = (newstate != 0) ? 1 : 0;
    
    // request connection of client to N148/21
    cmd_head.cmd = SOCKET_CMD_MGMT_CLIENT;
    cmd_head.address = htons( newstate );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get result
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_CMD_MGMT_CLIENT ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( -1 );
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
}


/*!
 * \brief extract byte value from buffer
 * 
 * \param   ptr             pointer to pointer to start of value, points to first byte after extracted value after call
 * 
 * \return                  value
 */
static uint8_t _get_byte( unsigned char **ptr )
{
    uint8_t     *p8;
    
    p8 = (uint8_t *)*ptr;
    (*ptr)++;
    return( *p8 );
}

/*!
 * \brief extract 16-bit integer value from buffer
 * 
 * \param   ptr             pointer to pointer to start of value, points to first byte after extracted value after call
 * 
 * \return                  value
 */
static uint16_t _get_word( unsigned char **ptr )
{
    uint16_t    *p16;
    
// printf( "%s\n", _hexdump( *ptr, 16, 1 ));
    p16 = (uint16_t *)*ptr;
    (*ptr) += 2;
    return( ntohs( *p16 ));
}

/*!
 * \brief extract 32-bit integer value from buffer
 * 
 * \param   ptr             pointer to pointer to start of value, points to first byte after extracted value after call
 * 
 * \return                  value
 */
static uint32_t _get_long( unsigned char **ptr )
{
    uint32_t    *p32;
    
// printf( "%s\n", _hexdump( *ptr, 4, 1 ));
    p32 = (uint32_t *)*ptr;
    (*ptr) += 4;
    return( ntohl( *p32 ));
}

/*!
 * \brief extract zero-terminated string from buffer
 * 
 * \param   ptr             pointer to pointer to start of value, points to first byte after extracted value after call
 * 
 * \return                  value
 */
static char *_get_string( unsigned char **ptr )
{
    char        *buf;
    
// printf( "%s\n", _hexdump( *ptr, 16, 1 ));
    buf = strdup( (char *)*ptr );
    (*ptr) += strlen( (char *)*ptr ) +1;
    
    return( buf );
}

/*!
 * \brief extract byte-sized string from buffer
 * 
 * \param   ptr             pointer to pointer to start of value, points to first byte after extracted value after call
 * 
 * \return                  value
 */
static char *_get_nstring( unsigned char **ptr )
{
    char        *buf;
    uint16_t    len;
    
// printf( "%s\n", _hexdump( *ptr, 16, 1 ));
    len = _get_word( ptr );
    if( len == 0 ) {
        return( NULL );
    }
    if( (buf = malloc( len +1 )) == NULL ) {
        (*ptr) += len;
        return( NULL );
    }
    
    memcpy( buf, *ptr, len );
    buf[len] = '\0';
    (*ptr) += len;
    
    return( buf );
}


/*!
 * \brief internal function to get status from server
 * 
 * \param   connInfo        pointer to active connection info block (as created by enmx_open())
 * 
 * \return                  pointer to newly allocated structure containing server status information
 */
static sENMX_Status *_getStatus( sConnectionInfo *connInfo )
{
    sENMX_Status            *status;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    unsigned char           *buf;
    unsigned char           *ptr;
    int                     loop;
    sENMX_StatusEIB         *p_eib;
    sENMX_StatusSocket      *p_client;
    sENMX_StatusEIBD        *p_eibd;

    // request connection of client to N148/21
    cmd_head.cmd = SOCKET_CMD_MGMT_STATUS;
    cmd_head.address = 0;
    ecode = connInfo->send( connInfo->socket, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    
    // get status
    ecode = connInfo->recv( connInfo->socket, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    if( rsp_head.status != SOCKET_CMD_MGMT_STATUS ) {
        connInfo->errorcode = _enmx_maperror( ntohs( rsp_head.size ));
        return( NULL );
    }
    rsp_head.size = ntohs( rsp_head.size );
    if( (buf = malloc( rsp_head.size )) == NULL ) {
        connInfo->errorcode = ENMX_E_NO_MEMORY;
        return( NULL );
    }
    ecode = connInfo->recv( connInfo->socket, buf, rsp_head.size, 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        free( buf );
        return( NULL );
    }
    
    if( (status = malloc( sizeof( sENMX_Status ))) == NULL ) {
        connInfo->errorcode = ENMX_E_NO_MEMORY;
        free( buf );
        return( NULL );
    }
    ptr = buf;
    status->status_version = _get_byte( &ptr );
    if( status->status_version > 2 ) {
        // does only support EIBnetmux status information version 1 & 2
        free( status );
        connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
        return( NULL );
    }
    ptr += 2;
    status->common.status_version = _get_byte( &ptr );
    if( status->common.status_version > 2 ) {
        // does only support EIBnetmux status, common information version 1 & 2
        free( status );
        connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
        return( NULL );
    }
    switch( status->common.status_version ) {
        case 1:
            asprintf( &status->common.version, "%d.%d", _get_byte( &ptr ), _get_byte( &ptr ));
            break;
        case 2:
            status->common.version = _get_string( &ptr );
            break;
    }
    status->common.loglevel = _get_word( &ptr );
    status->common.uptime = _get_long( &ptr );
    status->common.uid = _get_word( &ptr );
    status->common.gid = _get_word( &ptr );
    status->common.daemon = _get_byte( &ptr );
    
    ptr += 2;
    status->client.status_version = _get_byte( &ptr );
    if( status->client.status_version > 4 ) {
        // does only support EIBnetmux status, client information version 1 - 4
        free( status );
        connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
        return( NULL );
    }
    status->client.connected = _get_byte( &ptr );
    status->client.uptime = _get_long( &ptr );
    status->client.session_received = _get_long( &ptr );
    status->client.session_sent = _get_long( &ptr );
    status->client.total_received = _get_long( &ptr );
    status->client.total_sent = _get_long( &ptr );
    status->client.queue_len = _get_word( &ptr );
    status->client.missed_heartbeat = _get_word( &ptr );
    status->client.target_name = NULL;
    status->client.target_ip = 0;
    status->client.target_port = 0;
    status->client.source_ip = 0;
    status->client.loopback = 0;
    switch( status->client.status_version ) {
        case 1:
            break;
        case 2:
            ptr += 4;
            break;
        case 3:
            status->client.target_name = _get_nstring( &ptr );
            status->client.target_ip = htonl( _get_long( &ptr ));
            status->client.target_port = _get_word( &ptr );
            status->client.source_ip = htonl( _get_long( &ptr ));
            break;
        case 4:
            status->client.target_name = _get_nstring( &ptr );
            status->client.target_ip = htonl( _get_long( &ptr ));
            status->client.target_port = _get_word( &ptr );
            status->client.source_ip = htonl( _get_long( &ptr ));
            status->client.loopback = _get_byte( &ptr );
            break;
    }
    
    ptr += 2;
    status->server.status_version = _get_byte( &ptr );
    if( status->server.status_version > 4 ) {
        // does only support EIBnetmux status, eibnet/ip server information version 1 - 4
        free( status );
        connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
        return( NULL );
    }
    status->server.active = _get_byte( &ptr );
    status->server.port = _get_word( &ptr );
    status->server.max_connections = _get_byte( &ptr );
    status->server.nr_clients = _get_byte( &ptr );
    status->server.received = _get_long( &ptr );
    status->server.sent = _get_long( &ptr );
    status->server.queue_len = _get_word( &ptr );
    switch( status->server.status_version ) {
        default:
            status->server.default_level = -1;
            status->server.access_block = -1;
            break;
        case 4:
            status->server.default_level = _get_word( &ptr );
            status->server.access_block = _get_word( &ptr );
            break;
    }
    status->server.clients = NULL;
    
    for( loop = 0; loop < status->server.nr_clients; loop++ ) {
        if( (p_eib = malloc( sizeof( sENMX_StatusEIB ))) == NULL ) {
            enmx_mgmt_releasestatus( status );
            connInfo->errorcode = ENMX_E_NO_MEMORY;
            return( NULL );
        }
        if( status->server.status_version >= 4 ) {
            p_eib->conn_id = _get_long( &ptr );
        } else {
            p_eib->conn_id = 0;
        }
        p_eib->ip = htonl( _get_long( &ptr ));
        p_eib->port = _get_word( &ptr );
        p_eib->received = _get_long( &ptr );
        p_eib->sent = _get_long( &ptr );
        p_eib->queue_len = _get_word( &ptr );
        switch( status->server.status_version ) {
            case 1:
                p_eib->source_ip = 0;
                break;
            case 2:
                p_eib->source_ip = htonl( _get_long( &ptr ));
                break;
            case 3:
            case 4:
                p_eib->source_ip = htonl( _get_long( &ptr ));
                break;
        }
        p_eib->next = status->server.clients;
        status->server.clients = p_eib;
    }
    
    ptr += 2;
    status->socketserver.status_version = _get_byte( &ptr );
    if( status->socketserver.status_version > 5 ) {
        // does only support EIBnetmux status, socket server information version 1 - 5
        free( status );
        connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
        return( NULL );
    }
    status->socketserver.active_tcp = _get_byte( &ptr );
    status->socketserver.active_unix = _get_byte( &ptr );
    status->socketserver.port = _get_word( &ptr );
    status->socketserver.path = _get_string( &ptr );
    status->socketserver.max_connections = _get_byte( &ptr );
    status->socketserver.nr_clients = _get_byte( &ptr );
    status->socketserver.received = _get_long( &ptr );
    status->socketserver.sent = _get_long( &ptr );
    status->socketserver.queue_len = _get_word( &ptr );
    if( status->socketserver.status_version == 2 ) {
        ptr += 2;
    } else if( status->socketserver.status_version >= 3 ) {
        status->socketserver.authentication = _get_byte( &ptr );
    }
    status->socketserver.clients = NULL;
    ptr += 2;
    
    for( loop = 0; loop < status->socketserver.nr_clients; loop++ ) {
        if( (p_client = malloc( sizeof( sENMX_StatusSocket ))) == NULL ) {
            enmx_mgmt_releasestatus( status );
            connInfo->errorcode = ENMX_E_NO_MEMORY;
            return( NULL );
        }
        if( status->socketserver.status_version >= 5 ) {
            p_client->conn_id = _get_long( &ptr );
        } else {
            p_client->conn_id = 0;
        }
        p_client->ip = htonl( _get_long( &ptr ));
        p_client->port = _get_word( &ptr );
        p_client->received = _get_long( &ptr );
        p_client->sent = _get_long( &ptr );
        p_client->queue_len = 0; // _get_word( &ptr );
        if( status->socketserver.status_version >= 2 ) {
            p_client->name = _get_nstring( &ptr );
        } else {
            p_client->name = NULL;
        }
        if( status->socketserver.status_version >= 4 ) {
            p_client->user = _get_nstring( &ptr );
        } else {
            p_client->user = NULL;
        }
        p_client->next = status->socketserver.clients;
        status->socketserver.clients = p_client;
    }
    
    if( status->status_version > 1 ) {
        ptr += 2;
        status->eibd.status_version = _get_byte( &ptr );
        if( status->eibd.status_version > 1 ) {
            // does only support EIBnetmux status, eibd server information version 1
            free( status );
            connInfo->errorcode = ENMX_E_VERSIONMISMATCH;
            return( NULL );
        }
        status->eibd.active = _get_byte( &ptr );
        status->eibd.port = _get_word( &ptr );
        status->eibd.max_connections = _get_byte( &ptr );
        status->eibd.nr_clients = _get_byte( &ptr );
        status->eibd.received = _get_long( &ptr );
        status->eibd.sent = _get_long( &ptr );
        status->eibd.queue_len = _get_word( &ptr );
        status->eibd.clients = NULL;
        ptr += 2;
        
        for( loop = 0; loop < status->eibd.nr_clients; loop++ ) {
            if( (p_eibd = malloc( sizeof( sENMX_StatusEIBD ))) == NULL ) {
                enmx_mgmt_releasestatus( status );
                connInfo->errorcode = ENMX_E_NO_MEMORY;
                return( NULL );
            }
            p_eibd->conn_id = _get_long( &ptr );
            p_eibd->ip = htonl( _get_long( &ptr ));
            p_eibd->port = _get_word( &ptr );
            p_eibd->received = _get_long( &ptr );
            p_eibd->sent = _get_long( &ptr );
            p_eibd->next = status->eibd.clients;
            status->eibd.clients = p_eibd;
        }
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( status );
}

/*!
 * \endcond
 */

/*
static char _buf[BUFSIZ];
char *_hexdump( void *string, int len, int spaces )
{
    int             idx = 0;
    unsigned char   *ptr;

    if( string == NULL ) {
        return( NULL );
    }

    if( len == 0 )
        len = strlen( string );

    ptr = string;
    while( len > 0 ) {
        sprintf( &_buf[idx], "%2.2x", *ptr );
        idx +=2;
        if( spaces ) {
            sprintf( &_buf[idx], " " );
            idx++;
        }
        ptr++;
        len--;
    }

    return( _buf );
}
*/
/*! @} */
