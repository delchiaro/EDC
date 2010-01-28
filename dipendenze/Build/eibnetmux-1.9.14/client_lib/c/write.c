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
 *   \brief Write value to KNX group
 * \endif
 */
 
/*!
 * \example eibcommand.c
 * 
 * Demonstrates usage of the EIBnetmux group writing and data encoding functions.
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
 * \brief write value to group address
 * 
 * The data is used directly for the TPCI, APCI, and DATA part of the CEMI frame.
 * It must be preformatted accordingly.
 * In particular, the data must correspond to the EIS data type assigned to the addressed KNX group.
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * \param   value           byte stream
 * \param   length          length of byte stream
 * 
 * \return                  0: ok, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 */
int enmx_write( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t length, unsigned char *value )
{
    sConnectionInfo         *connInfo;
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    uint16_t                data_len;
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( ENMX_E_NO_CONNECTION );
    }

    // check state
    if( connInfo->state != stateUnused && connInfo->state != stateWrite ) {
        connInfo->errorcode = ENMX_E_WRONG_USAGE;
        return( -1 );
    }
    
    // request sending connection
    cmd_head.cmd = SOCKET_CMD_WRITE;
    cmd_head.address = htons( knxaddress );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    connInfo->state = stateWrite;
    
    // append data
    data_len = htons( length );
    ecode = connInfo->send( handle, (unsigned char *)&data_len, sizeof( data_len ));
    if( ecode == 0 ) {
        ecode = connInfo->send( handle, value, length );
    }
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }

    // get acknowledgement
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_WRITE ) {
        connInfo->errorcode = ENMX_E_INTERNAL;
        return( -1 );
    }
    
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
}
/*! @} */
