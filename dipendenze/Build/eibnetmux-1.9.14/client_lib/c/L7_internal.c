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
 *   \brief Layer 7 API - internal helper functions
 * \endif
 */

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"


/*
 * local functions
 */
static int  _enmx_L7SendAckNak( sConnectionInfo *pConn, ENMX_ADDRESS knxaddress, uint8_t tpci, uint8_t acknak );
static int  _enmx_L7CheckResponse( CEMIFRAME *cemi, uint8_t tpci, uint16_t apci, int sequence );
static int  _enmx_L7MapError( uint16_t error );


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief initialise layer 7/passthrough connection to eibnetmux
 * 
 * \param   pConn           pointer to connection structure
 * \param   knxaddress      physical address of remote device
 * 
 * \return                  0: ok, -1: error
 */
int _enmx_L7Passthrough( sConnectionInfo *pConn, ENMX_ADDRESS knxaddress )
{
    SOCKET_CMD_HEAD         cmd_head;
    int                     ecode;
    
    // request passthrough connection
    cmd_head.cmd = SOCKET_CMD_PASSTHROUGH;
    cmd_head.address = htons( knxaddress );
    ecode = pConn->send( pConn->socket, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        pConn->errorcode = ecode;
        return( -1 );
    }
    pConn->state = stateLayer7;
    
    return( 0 );
}


/*!
 * \brief check TCPI for match
 * 
 * \param   cemi            pointer to CEMI frame
 * \param   tpci            required transport control field setting
 * \param   apci            required application control field setting
 * \param   sequence        required sequence number
 * 
 * \return                  =0: TPCI matches, -1: no match
 */
static int _enmx_L7CheckResponse( CEMIFRAME *cemi, uint8_t tpci, uint16_t apci, int sequence )
{
    if( tpci == T_DATA_REQ_PDU ) {
        if( (cemi->tpci & 0xfc) != (tpci | ((sequence & 0x0f) << 2)) ) {
            return( -1 );
        }
    } else if( tpci == T_CONNECT_CONF_PDU ) {
        if( cemi->tpci == tpci ) {
            return( 0 );
        } else {
            return( -1 );
        }
    }
    if( cemi->length == 0 ) {
        return( 0 );
    }
    if( (cemi->tpci & 0x03) != (apci & 0x0300) >> 8 ) {
        return( -1 );
    }
    switch( apci ) {
        case A_READ_ADC_RES_PDU:
            if( (cemi->apci & 0xc0) != (apci & 0x00ff) ) {
                return( -1 );
            }
            break;
        case A_READ_MEMORY_RES_PDU:
            if( (cemi->apci & 0xf0) != (apci & 0x00ff) ) {
                return( -1 );
            }
            break;
        default:
            if( cemi->apci != (apci & 0x00ff) ) {
                return( -1 );
            }
            break;
    }
    return( 0 );
}


/*!
 * \brief check layer 7 connection state
 * 
 * \param   pConn           pointer to connection structure
 * 
 * \return                  0: ok, -1: wrong state
 */
int _enmx_L7State( sConnectionInfo *pConn )
{
    if( pConn->L7connection == 0 ) {
        return( 0 );
    }
    
    pConn->errorcode = ENMX_E_L7_NO_CONNECTION;
    return( -1 );
}


/*!
 * \brief send Ack to confirm receiption of layer 7 connection request/response
 * 
 * \param   pConn           pointer to connection structure
 * 
 * \return                  0: ok, -1: wrong state
 */
static int _enmx_L7SendAckNak( sConnectionInfo *pConn, ENMX_ADDRESS knxaddress, uint8_t tpci, uint8_t acknak )
{
    sLayer7Params   params;
    int             ecode;
    
    if( _enmx_L7Passthrough( pConn, knxaddress ) != 0 ) {
        return( -1 );
    }
    
    params.length = 0;
    params.tpci = acknak | (tpci & 0x3c);
    params.apci = 0;
    params.priority = ENMX_PRIO_SYSTEM;
    ecode = pConn->send( pConn->socket, (unsigned char *)&params, sizeof( params ));
    if( ecode < 0 ) {
        pConn->errorcode = ecode;
        return( -1 );
    }
    return( 0 );
}


/*!
 * \brief map error code
 * 
 * \param   error           error code returned by eibnetmux server
 * 
 * \return                  error code mapped to library codes
 */
static int _enmx_L7MapError( uint16_t error )
{
    switch( error ) {
        case 1:
            return( ENMX_E_COMMUNICATION );
            break;
        case 2:
            return( ENMX_E_SERVER_ABORTED );
            break;
        case 3:
            return( ENMX_E_INTERNAL );
            break;
        case 4:
            return( ENMX_E_INTERNAL );
            break;
        case 5:
            return( ENMX_E_TIMEOUT );
            break;
        case 6:
            return( ENMX_E_UNAUTHORISED );
            break;
        case 7:
            return( ENMX_E_AUTH_FAILURE );
            break;
        case 8:
            return( ENMX_E_DHM_FAILURE );
            break;
        case 9:
            return( ENMX_E_PARAMETER );
            break;
    }
    return( ENMX_E_INTERNAL );
}


/*!
 * \brief get layer 7 Ack/Nak
 * 
 * \param   pConn           pointer to connection structure
 * 
 * \return                  0: Ack received, 1: NAK received, -1: error
 */
int _enmx_L7GetAckNak( sConnectionInfo *pConn )
{
    SOCKET_RSP_HEAD     rsp_head;
    CEMIFRAME           *cemi;
    int                 ecode;
    
    // get acknowledgement
    // we will receive the full cemi frame and extract the response code (which must be T_CONNECT_CONF_PDU)
    ecode = pConn->recv( pConn->socket, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        pConn->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_PASSTHROUGH ) {
        if( rsp_head.status == SOCKET_STAT_ERROR ) {
            // map eibnetmux socketserver result codes to client library result codes
            pConn->errorcode = _enmx_L7MapError( rsp_head.size );
        } else {
            pConn->errorcode = ENMX_E_INTERNAL;
        }
        return( -1 );
    }
    rsp_head.size = ntohs( rsp_head.size );
    if( (cemi = (CEMIFRAME *)malloc( rsp_head.size )) == NULL ) {
        pConn->errorcode = ENMX_E_NO_MEMORY;
        return( -1 );
    }
    ecode = pConn->recv( pConn->socket, (unsigned char *)cemi, rsp_head.size, 1 );
    if( ecode == 0 ) {
        if( cemi->length == 0 ) {
            if( cemi->tpci == (T_DATA_ACK_PDU | ((pConn->L7sequence_id & 0xff) << 2)) ) {
                return( 0 );
            }
        }
        return( 1 );
    }
    return( ecode );
}


/*!
 * \brief get and check response to last layer 7 request
 * 
 * \param   pConn           pointer to connection structure
 * \param   knxaddress      physical address of remote device
 * \param   buf             pointer to buffer receiving data (tpci, apci, data)
 * \param   length          pointer to variable specifying maximum size of data buffer, receives actual length of received data
 * \param   tpci            required transport control field setting
 * \param   apci            required application control field setting
 * 
 * \return                  0: ok, -1: error (errorcode set accordingly)
 */
int _enmx_L7Response( sConnectionInfo *pConn, ENMX_ADDRESS knxaddress, unsigned char *buf, int *length, uint8_t tpci, uint16_t apci )
{
    SOCKET_RSP_HEAD     rsp_head;
    CEMIFRAME           *cemi;
    int                 ecode;
    
    // get acknowledgement
    // we will receive the full cemi frame and extract the response code
    ecode = pConn->recv( pConn->socket, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        pConn->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_PASSTHROUGH ) {
        if( rsp_head.status == SOCKET_STAT_ERROR ) {
            // map eibnetmux socketserver result codes to client library result codes
            pConn->errorcode = _enmx_L7MapError( rsp_head.size );
        } else {
            pConn->errorcode = ENMX_E_INTERNAL;
        }
        return( -1 );
    }
    rsp_head.size = ntohs( rsp_head.size );
    if( (cemi = (CEMIFRAME *)malloc( rsp_head.size )) == NULL ) {
        pConn->errorcode = ENMX_E_NO_MEMORY;
        return( -1 );
    }
    ecode = pConn->recv( pConn->socket, (unsigned char *)cemi, rsp_head.size, 1 );
    if( ecode == 0 ) {
        if( _enmx_L7CheckResponse( cemi, tpci, apci, pConn->L7sequence_id )) {
            (void) _enmx_L7SendAckNak( pConn, knxaddress, cemi->tpci, T_DATA_NAK_PDU );
            pConn->errorcode = ENMX_E_L7_SEQUENCE;
            ecode = -1;
        } else if( buf != NULL ) {
            if( *length < cemi->length +1 ) {
                pConn->errorcode = ENMX_E_L7_BUFSIZE;
                ecode = -1;
            } else {
                memcpy( buf, &cemi->tpci, cemi->length +1 );
                *length = cemi->length +1;
            }
            (void) _enmx_L7SendAckNak( pConn, knxaddress, cemi->tpci, T_DATA_ACK_PDU );
        }
    } else {
        pConn->errorcode = ecode;
        ecode = -1;
    }
    free( cemi );
    
    return( ecode );
}
/*! @} */
