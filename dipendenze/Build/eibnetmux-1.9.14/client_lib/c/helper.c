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
 *   \brief Internal helper functions
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
 * \addtogroup xgHelper
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

/*!
 * \brief find connection info structure for given handle
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  NULL: not found, pointer to structure otherwise
 */
sConnectionInfo *_enmx_connectionGet( ENMX_HANDLE handle )
{
    sConnectionInfo     *pConn;
    
    for( pConn = enmx_connections; pConn != NULL; pConn = pConn->next ) {
        if( pConn->socket == handle ) {
            break;
        }
    }
    return( pConn );
}


/*!
 * \brief verify that connection is in a usable state
 * 
 * \param   pConn           pointer to connection structure
 * \param   state           state connection must be in
 * 
 * \return                  0: ok, -1: wrong state
 */
int _enmx_connectionState( sConnectionInfo *pConn, int state )
{
    // check state
    if( pConn->state == stateUnused || pConn->state == state ) {
        return( 0 );
    }
    
    pConn->errorcode = ENMX_E_WRONG_USAGE;
    return( -1 );
}

/*!
 * \endcond
 */
/*! @} */
