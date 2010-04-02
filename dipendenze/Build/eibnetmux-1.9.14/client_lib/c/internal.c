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
 *   \brief Internal functions - standard versions
 * \endif
 */

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#include "enmx_lib.private.h"

/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

/*!
 * \brief send a byte stream to the server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   buf             pointer to buffer
 * \param   length          length of buffer
 * 
 * \return                  0: ok, -1: error
 */
int _enmx_send( ENMX_HANDLE handle, unsigned char *buf, uint16_t length )
{
    time_t          now;
    int             flags;
    int             result;
    
    result = ENMX_E_NO_ERROR;
    flags = fcntl( handle, F_GETFL );
    fcntl( handle, F_SETFL, flags | O_NONBLOCK );
    now = time( NULL );
    while( write( handle, buf, length ) == -1 ) {
        if( errno == EAGAIN ) {
            if( now + TIMEOUT <= time( NULL )) {
                result = ENMX_E_TIMEOUT;
                break;
            }
            usleep( 10 * 1000 );
                continue;
        } else {
            result = ENMX_E_COMMUNICATION;
            break;
        }
    }
    fcntl( handle, F_SETFL, flags );
    
    return( result );
}


/*!
 * \brief receive a byte stream from the server
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   buf             pointer to receive buffer
 * \param   length          length of byte stream to receive
 * \param   timeout         maximum time to wait to get all data
 * 
 * \return                  0: ok, -1: error
 */
int _enmx_receive( ENMX_HANDLE handle, unsigned char *buf, uint16_t length, int timeout )
{
    time_t          now;
    int             len;
    int             bytes;
    int             flags;
    int             result;
    
    result = ENMX_E_NO_ERROR;
    flags = fcntl( handle, F_GETFL );
    if( timeout != 0 ) {
        fcntl( handle, F_SETFL, flags | O_NONBLOCK );
    }
    now = time( NULL );
    for( len = 0; len < length; ) {
        if( (bytes = read( handle, buf, length - len )) == -1 ) {
            if( errno == EAGAIN ) {
                if( now + TIMEOUT <= time( NULL )) {
                    result = ENMX_E_TIMEOUT;
                    break;
                }
                usleep( 10 * 1000 );
                continue;
            } else {
                result = ENMX_E_COMMUNICATION;
                break;
            }
        }
        if( bytes == 0 ) {
            result = ENMX_E_SERVER_ABORTED;
            break;
        }
        len += bytes;
    }
    fcntl( handle, F_SETFL, flags );

    return( result );
}


/*!
 * \brief map eibnetmux server's error code to library error
 * 
 * \param   code            error code returned by eibnetmux server
 * 
 * \return                  mapped error code
 */
int _enmx_maperror( int code )
{
    switch( code ) {
        case E_NO_ERROR:
            return( ENMX_E_NO_ERROR );
        case E_UNAUTHORISED:
            return( ENMX_E_UNAUTHORISED );
        case E_PARAMETER:
            return( ENMX_E_PARAMETER );
    }
    return( ENMX_E_INTERNAL );
}


/*!
 * \brief wait a little while
 * 
 * \param   msec            milliseconds to wait
 */
void _enmx_wait( int msec )
{
    usleep( 1000 * msec );
}


/*!
 * \endcond
 */

/*
static char _buf[BUFSIZ];
char *_enmx_hexdump( void *string, int len, int spaces )
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
