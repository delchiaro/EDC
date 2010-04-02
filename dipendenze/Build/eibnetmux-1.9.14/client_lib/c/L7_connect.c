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
 *   \brief Layer 7 API - establish connection with remote device
 * \endif
 */
 
/*!
 * \example layer7.c
 * 
 * Demonstrates usage of the EIBnetmux layer 7 API.
 */

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"

/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief connect to remote KNX device
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * 
 * \return                  0: ok, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 */
int enmx_L7_connect( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress )
{
    sConnectionInfo         *connInfo;
    sLayer7Params           params;
    unsigned char           buf[4];
    int                     len = 4;
    uint16_t                *mask;
    int                     loop;
    int                     ecode;
    
    // get connection info block
    if( (connInfo = _enmx_connectionGet( handle )) == NULL ) {
        return( ENMX_E_NO_CONNECTION );
    }
    if( _enmx_connectionState( connInfo, stateLayer7 ) != 0 ) {
        return( -1 );
    }
    
    // request passthrough connection
    if( _enmx_L7Passthrough( connInfo, knxaddress ) != 0 ) {
        return( -1 );
    }
    
    // connect to remote device
    // - there won't be any confirmation ?!?
    params.length = 0;
    params.tpci = T_CONNECT_REQ_PDU;
    params.apci = 0;
    params.priority = ENMX_PRIO_SYSTEM;
    ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    connInfo->L7connection = 0;
    connInfo->L7sequence_id = 0;
    
    // get mask version
    for( loop = 0; loop < ENMX_L7_MAXREPEAT; loop++ ) {
        if( _enmx_L7Passthrough( connInfo, knxaddress ) != 0 ) {
            return( -1 );
        }
        params.length = 1;
        params.tpci = T_DATA_REQ_PDU | ((A_READ_MASK_VERSION_REQ_PDU & 0x0300) >> 8) | ((connInfo->L7sequence_id & 0x0f) << 2);
        params.apci = (A_READ_MASK_VERSION_REQ_PDU & 0x00ff);
        params.priority = ENMX_PRIO_SYSTEM;
        ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
        if( ecode < 0 ) {
            connInfo->errorcode = ecode;
            return( -1 );
        }
        if( _enmx_L7GetAckNak( connInfo ) != 0 ) {
            if( connInfo->errorcode == ENMX_E_TIMEOUT ) {
                // connInfo->wait( ENMX_L7_REPEAT_DELAY );
                continue;
            }
            return( -1 );
        }
        
        if( (ecode = _enmx_L7Response( connInfo, knxaddress, buf, &len, T_DATA_REQ_PDU, A_READ_MASK_VERSION_RES_PDU )) != 0 ) {
            if( connInfo->errorcode == ENMX_E_TIMEOUT ) {
                // connInfo->wait( ENMX_L7_REPEAT_DELAY );
                continue;
            }
            return( -1 );
        }
        if( ++connInfo->L7sequence_id > 15 ) {
            connInfo->L7sequence_id = 0;
        }
        mask = (uint16_t *) &buf[2];
        if( ntohs( *mask ) < 0x12 ) {
            connInfo->errorcode = ENMX_E_L7_MASK;
            return( -1 );
        } else {
            return( 0 );
        }
    }
    return( -1 );
}


/*!
 * \brief connect to remote KNX device
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * 
 * \return                  0: ok, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 */
int enmx_L7_disconnect( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress )
{
    sConnectionInfo         *connInfo;
    sLayer7Params           params;
    int                     ecode;
    
    // get connection info block
    if( (connInfo = _enmx_connectionGet( handle )) == NULL ) {
        return( ENMX_E_NO_CONNECTION );
    }
    if( _enmx_connectionState( connInfo, stateLayer7 ) != 0 ) {
        return( -1 );
    }
    if( _enmx_L7State( connInfo ) != 0 ) {
        return( -1 );
    }
    
    // request passthrough connection
    if( _enmx_L7Passthrough( connInfo, knxaddress ) != 0 ) {
        return( -1 );
    }
    
    // send parameters
    params.length = 0;
    params.tpci = T_DISCONNECT_REQ_PDU;
    params.apci = 0;
    params.priority = ENMX_PRIO_SYSTEM;
    ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // there won't be any confirmation from the remote side
    connInfo->L7connection = 0;
    connInfo->L7sequence_id = 0;
    
    return( 0 );
}
/*! @} */
