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
 *   \brief Layer 7 API - reset remote device
 * \endif
 */
 
/*!
 * \example layer7.c
 * 
 * Demonstrates usage of the EIBnetmux layer 7 API.
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#include "enmx_lib.private.h"


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief reset remote KNX device
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * 
 * \return                  =0: ok, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 */
int enmx_L7_reset( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress )
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
    params.length = 1;
    params.tpci = T_DATA_REQ_PDU | ((A_RESTART_REQ_PDU & 0x0300) >> 8) | ((connInfo->L7sequence_id & 0x0f) << 2);
    params.apci = (A_RESTART_REQ_PDU & 0x00ff);
    params.priority = ENMX_PRIO_SYSTEM;
    ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // Commented out as I assume that there is no confirmation
    /*
    if( _enmx_L7GetAckNak( connInfo ) != 0 ) {
        return( -1 );
    }
    */
    return( 0 );
}
/*! @} */
