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
 *   \brief Initialisation
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
 * \addtogroup xgSetup
 * @{
 */

/*!
 * \brief initialise eibnetmux client library
 * 
 * Currently, this function does nothing but return the current API version number.
 * Calling it first thing in a client application is enforced, however,
 * as future enhancements may require initialisation before any other
 * library function can be used.
 * 
 * \return                  API version number
 */
int enmx_init( void )
{
    enmx_mode = ENMX_LIB_INITIALISED;
    
    return( ENMX_VERSION_API );
}
/*! @} */
