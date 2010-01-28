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
 *   \brief Monitor KNX groups
 * \endif
 */
 
/*!
 * \example eibtrace.c
 * 
 * Demonstrates usage of the EIBnetmux monitoring function.
 * 
 * It produces a trace of requests seen on the KNX bus.
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief monitor group addresses
 * 
 * Use this function to monitor the activity on the KNX bus.
 * This function is similar to a simple read but returns all requests
 * addressed to a set of KNX logical groups.
 * 
 * For each request, the complete CEMI frame is returned. The caller must
 * understand its format and extract the data according to the addressed
 * group's EIS data type.
 * 
 * ATTENTION:
 *      caller has to release returned buffer
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   mask            mask of knx group addresses to monitor (as 16-bit integer)
 * \param   buf             buffer which will receive byte stream, enlarged if required
 * \param   buflen          pointer to current size of buffer, updated if buffer enlarged
 * \param   length          pointer to variable which will receive length of byte stream
 * 
 * \return                  pointer to received byte stream or NULL upon error (get error code with enmx_geterror)
 */
unsigned char *enmx_monitor( ENMX_HANDLE handle, ENMX_ADDRESS mask, unsigned char *buf, uint16_t *buflen, uint16_t *length )
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
        return( NULL );
    }

    // check state
    if( connInfo->state == stateUnused ) {
        // request monitoring connection
        cmd_head.cmd = SOCKET_CMD_MONITOR;
        cmd_head.address = mask;
        ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
        if( ecode < 0 ) {
            connInfo->errorcode = ecode;
            return( NULL );
        }
        connInfo->state = stateMonitor;
    }
    if( connInfo->state != stateMonitor ) {
        connInfo->errorcode = ENMX_E_WRONG_USAGE;
        return( NULL );
    }
    
    // get value
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 0 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    if( rsp_head.status != SOCKET_STAT_MONITOR ) {
        connInfo->errorcode = ENMX_E_INTERNAL;
        return( NULL );
    }
    rsp_head.size = ntohs( rsp_head.size );
    if( buf == NULL || buflen == NULL ) {
        buf = malloc( rsp_head.size );
        if( buflen != NULL ) *buflen = rsp_head.size;
    } else if( *buflen < rsp_head.size ) {
        *buflen = rsp_head.size;
        buf = realloc( buf, *buflen );
    }
    if( buf == NULL ) {
        connInfo->errorcode = ENMX_E_NO_MEMORY;
        return( NULL );
    }
    ecode = connInfo->recv( handle, buf, rsp_head.size, 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    
    if( length != NULL ) {
        *length = rsp_head.size;
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( buf );
}
/*! @} */
