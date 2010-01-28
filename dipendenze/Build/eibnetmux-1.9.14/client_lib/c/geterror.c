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
 *   \brief Error handling
 * \endif
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"

/*!
 * \addtogroup xgError
 * @{
 */

/*!
 * \if DeveloperDocs
 * \brief human readable error messages for every error code
 * \endif
 */
static char *_messages[] = {
        "No error",
        "Communication error",
        "Server closed connection",
        "Unknown group",
        "Internal error",
        "Out of memory",
        "Timeout while sending/receiving",
        "Connection was already used for different command",
        "Authentication is not supported (either by server or by library)",
        "User authentication failed (wrong username/password)",
        "DHM key exchange failed",
        "Invalid parameter passed to library",
        "Not authorised to perform this function",
        "Specified host could not be found, no ip address available",
        "Either none or more than one EIBnetmux server(s) found - specify target host",
        "EIBnetmux not running on host (or socketserver not activated)",
        "Library not initialised, call enmx_init()",
        "Client identifier must be specified",
        "Unable to register client identifier",
        "System resource problem"
        "Invalid connection handle",
        "Library does not match/support version of EIBnetmux server",
        "No connection with other device established",
        "Remote device replied with NAK",
        "Remote device's answer was not what we expected",
        "Buffer not large enough to receive all data",
        "Invalid mask version of remote device",
};

/*!
 * \if DeveloperDocs
 * \brief human readable error messages for unknown error codes
 * \endif
 */
static char *_unknown = "Unknown error";


/*!
 * return error code of last operation
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * 
 * \return                  error code of last operation
 */
int enmx_geterror( ENMX_HANDLE handle )
{
    sConnectionInfo         *connInfo;

    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( ENMX_E_NO_CONNECTION );
    } else {
        return( connInfo->errorcode );
    }
}


/*!
 * \brief return error message of last operation
 * 
 * \param   errno           error code as returned by enmx_open() or enmx_geterror()
 * 
 * \return                  error message as string
 */
char *enmx_errormessage( int errno )
{
    if( errno > 0 || errno < -26 ) {
        return( _unknown );
    }
    
    return( _messages[ -errno ]);
}
/*! @} */
