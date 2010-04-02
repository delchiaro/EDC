/*
 * zLogger - logging library for C
 * Copyright (C) 2008 Urs Zurbuchen <going_nuts@sourceforge.net>
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
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "zlogger.private.h"

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
        "Invalid parameters",
        "Out of memory",
        "Invalid logger id",
        "Invalid format id",
        "Invalid appender id",
        "Problem writing data to log channel",
        "Invalid syslog facility",
        "Unable to load plugin",
        "Invalid plugin specified",
        "Invalid log level specified",
        "No appender found for selected type",
};

/*!
 * \if DeveloperDocs
 * \brief human readable error messages for unknown error codes
 * \endif
 */
static char *_unknown = "Unknown error";


/*!
 * \brief return error message of last operation
 * 
 * \param   errno           error code as returned by zlogErrorCode()
 * 
 * \return                  error message as string
 */
char *zlogErrorString( int errno )
{
    if( errno > 0 || errno < ZLOG_E_LAST_ERRNO ) {
        return( _unknown );
    }
    
    return( _messages[ -errno ]);
}
/*! @} */
