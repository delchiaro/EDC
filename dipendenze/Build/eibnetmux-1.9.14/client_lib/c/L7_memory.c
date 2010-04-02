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
 *   \brief Layer 7 API - read/write memory of remote device
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
#include <string.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"

#define CHUNKSIZE           12


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief read memory of remote KNX device
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * \param   offset          start address of memory to read
 * \param   length          number of bytes to read
 * \param   buf             buffer receiving read bytes
 * 
 * \return                  >=0: number of bytes read, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 *                          if number of bytes read is less then requested length, there was an error
 */
int enmx_L7_readmemory( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t offset, uint16_t length, unsigned char *buf )
{
    sConnectionInfo         *connInfo;
    sLayer7Params           params;
    unsigned char           data[16];
    unsigned char           *ptr;
    uint16_t                bytes;
    int                     len;
    int                     chunkSize;
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
    
    // memory is read in chunk of 12 bytes
    ptr = buf;
    bytes = 0;
    while( bytes < length ) {
        if( _enmx_L7Passthrough( connInfo, knxaddress ) != 0 ) {
            return( -1 );
        }
        
        // send parameters
        params.length = 3;
        params.tpci = T_DATA_REQ_PDU | ((A_READ_MEMORY_REQ_PDU & 0x0300) >> 8) | ((connInfo->L7sequence_id & 0x0f) << 2);
        params.apci = (A_READ_MEMORY_REQ_PDU & 0x00ff);
        if( length - bytes >= CHUNKSIZE ) {
            chunkSize = CHUNKSIZE;
        } else {
            chunkSize = (length - bytes);
        }
        params.apci |= chunkSize;
        params.priority = ENMX_PRIO_SYSTEM;
        data[0] = (( offset + bytes ) & 0xff00) >> 8;
        data[1] = ( offset + bytes ) & 0x00ff;
        ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
        if( ecode == 0 ) {
            ecode = connInfo->send( handle, data, 2 );
        }
        if( ecode < 0 ) {
            connInfo->errorcode = ecode;
            return( bytes );
        }
        
        if( _enmx_L7GetAckNak( connInfo ) != 0 ) {
            return( bytes );
        }
        
        len = 16;
        if( _enmx_L7Response( connInfo, knxaddress, data, &len, T_DATA_REQ_PDU, A_READ_MEMORY_RES_PDU ) != 0 ) {
            return( bytes );
        }
        if( len <= 4 ) {
            return( bytes );
        }
        memcpy( ptr, &data[4], len -4 );
        bytes += len -4;
        ptr += len -4;
        if( ++connInfo->L7sequence_id > 15 ) {
            connInfo->L7sequence_id = 0;
        }
    }
    
    return( bytes );
}


/*!
 * \brief write memory of remote KNX device
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   knxaddress      knx group address as 16-bit integer
 * \param   offset          start address of memory to read
 * \param   length          number of bytes to read
 * \param   buf             bytes to write
 * 
 * \return                  >=0: number of bytes written, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 *                          if number of bytes written is less then requested length, there was an error
 */
int enmx_L7_writememory( ENMX_HANDLE handle, ENMX_ADDRESS knxaddress, uint16_t offset, uint16_t length, unsigned char *buf )
{
    sConnectionInfo         *connInfo;
    sLayer7Params           params;
    unsigned char           data[16];
    unsigned char           *ptr;
    uint16_t                bytes;
    int                     chunkSize;
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
    
    // memory is written in chunk of 12 bytes
    ptr = buf;
    bytes = 0;
    while( bytes < length ) {
        if( _enmx_L7Passthrough( connInfo, knxaddress ) != 0 ) {
            return( -1 );
        }
        
        // send parameters
        if( length - bytes >= CHUNKSIZE ) {
            chunkSize = CHUNKSIZE;
        } else {
            chunkSize = (length - bytes);
        }
        params.length = chunkSize +3;
        params.tpci = T_DATA_REQ_PDU | ((A_WRITE_MEMORY_REQ_PDU & 0x0300) >> 8) | ((connInfo->L7sequence_id & 0x0f) << 2);
        params.apci = (A_WRITE_MEMORY_REQ_PDU & 0x00ff);
        params.apci |= chunkSize;
        params.priority = ENMX_PRIO_SYSTEM;
        data[0] = (( offset + bytes ) & 0xff00) >> 8;
        data[1] = ( offset + bytes ) & 0x00ff;
        memcpy( &data[2], ptr, chunkSize );
        ecode = connInfo->send( handle, (unsigned char *)&params, sizeof( params ));
        if( ecode == 0 ) {
            ecode = connInfo->send( handle, data, chunkSize +2 );
        }
        if( ecode < 0 ) {
            connInfo->errorcode = ecode;
            return( bytes );
        }
        
        if( _enmx_L7GetAckNak( connInfo ) != 0 ) {
            return( bytes );
        }
        
        bytes += chunkSize;
        ptr += chunkSize;
        if( ++connInfo->L7sequence_id > 15 ) {
            connInfo->L7sequence_id = 0;
        }
    }
    
    return( bytes );
}
/*! @} */
