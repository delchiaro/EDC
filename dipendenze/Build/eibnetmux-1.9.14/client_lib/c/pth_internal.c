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
 *   \brief Internal functions, PTH versions
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

#include <pth.h>

#include "enmx_lib.private.h"


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief send a byte stream to the server (PTH version)
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   buf             pointer to buffer
 * \param   length          length of buffer
 * 
 * \return                  0: ok, -1: error
 */
int _enmx_pth_send( ENMX_HANDLE handle, unsigned char *buf, uint16_t length )
{
    pth_event_t             ev_wakeup;
    time_t                  secs;
    int                     result;
    
    secs = time( NULL ) + TIMEOUT;
    ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));

    if( pth_write_ev( handle, buf, length, ev_wakeup ) == length ) {
        result = ENMX_E_NO_ERROR;
    } else {
        if( pth_event_status( ev_wakeup ) == PTH_STATUS_OCCURRED ) {
            // timeout
            result = ENMX_E_TIMEOUT;
        } else {
            result = ENMX_E_COMMUNICATION;
        }
    }
    
    pth_event_free( ev_wakeup, PTH_FREE_ALL );
    
    return( result );
}


/*!
 * \brief receive a byte stream from the server (PTH version)
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   buf             pointer to receive buffer
 * \param   length          length of byte stream to receive
 * \param   timeout         maximum time to wait to get all data
 * 
 * \return                  0: ok, -1: error
 */
int _enmx_pth_receive( ENMX_HANDLE handle, unsigned char *buf, uint16_t length, int timeout )
{
    pth_event_t             ev_wakeup;
    time_t                  secs;
    int                     len;
    int                     bytes;
    int                     result;
    
    secs = time( NULL ) + TIMEOUT;
    ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));

    result = ENMX_E_NO_ERROR;
    for( len = 0; len < length; ) {
        if( timeout != 0 ) {
            bytes = pth_read_ev( handle, buf + len, length - len, ev_wakeup );
            if( pth_event_status( ev_wakeup ) == PTH_STATUS_OCCURRED ) {
                result = ENMX_E_TIMEOUT;
                break;
            } else if( bytes < 0 ) {
                result = ENMX_E_COMMUNICATION;
                break;
            }
        } else {
            if( (bytes = pth_read( handle, buf + len, length - len )) == -1 ) {
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
    
    pth_event_free( ev_wakeup, PTH_FREE_ALL );
    
    return( result );
}


/*!
 * \brief wait a little while (PTH version)
 * 
 * \param   msec            milliseconds to wait
 */
void _enmx_pth_wait( int msec )
{
    pth_usleep( 1000 * msec );
}
/*!
 * \endcond
 */
/*! @} */
