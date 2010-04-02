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
 *   \brief Read value from KNX group
 * \endif
 */
 
/*!
 * \example eibread.c
 * 
 * Demonstrates usage of the EIBnetmux group reading and data decoding functions.
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
 * \brief read value from group address
 * 
 * Returned data comes directly from the CEMI frame and must be analysed according to
 * the KNX group's EIS data type.
 * 
 * ATTENTION:
 *      caller has to release returned buffer
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * \param   length          pointer to variable which will receive length of byte stream
 * 
 * \return                  pointer to received byte stream or NULL upon error (get error code with enmx_geterror)
 */
unsigned char *enmx_read( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t *length )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    unsigned char           *buf;
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
    if( connInfo->state != stateUnused && connInfo->state != stateRead ) {
        connInfo->errorcode = ENMX_E_WRONG_USAGE;
        return( NULL );
    }
    
    // request reading connection
    cmd_head.cmd = SOCKET_CMD_READ;
    cmd_head.address = htons( knxaddress );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    connInfo->state = stateRead;
    
    // get value
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( NULL );
    }
    if( rsp_head.status != SOCKET_STAT_READ ) {
        connInfo->errorcode = ENMX_E_INTERNAL;
        return( NULL );
    }
    rsp_head.size = ntohs( rsp_head.size );
    if( (buf = malloc( rsp_head.size )) == NULL ) {
        connInfo->errorcode = ENMX_E_NO_MEMORY;
        return( NULL );
    }
    ecode = connInfo->recv( handle, buf, rsp_head.size, 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        free( buf );
        return( NULL );
    }
    
    if( length != NULL ) {
        *length = rsp_head.size;
    }
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( buf );
}
/*! @} */
