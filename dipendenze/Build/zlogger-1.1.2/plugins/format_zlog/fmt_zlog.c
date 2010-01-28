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
 *   \brief Plugin sample format
 * \endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "zlogger.private.h"

#define ZLOG_FMT_PLUGIN_LABEL   "zLog"
    

/*!
 * \addtogroup xgFormat
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

/*
 * Local function declarations
 */
static int  zlogPrintf( char *dest, int maxlen, struct timeval *tv );
static int  zlogLength( struct timeval *tv );


/*
 * Local variables
 */
static sFormatPlugin     structFormat = {
        'Z', zlogPrintf, zlogLength, NULL
};


/*!
 * \brief return plugin type
 * 
 * \return                  zlogPluginAppender
 */
eZLogPluginType zlogPlugin_GetType( void )
{
    return( zlogPluginFormat );
}


/*!
 * \brief init zlog format plugin
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
sFormatPlugin *zlogPlugin_Init( void )
{
    return( &structFormat );
}


/*!
 * \brief insert formatted part of log entry
 * 
 * \param   dest            destination buffer
 * \param   maxlen          maximum size of formatted string
 * \param   tv              time of log entry
 * 
 * \return                  number of characters inserted into destination buffer, <0: error
 */
static int zlogPrintf( char *dest, int maxlen, struct timeval *tv )
{
    if( maxlen < strlen( ZLOG_FMT_PLUGIN_LABEL ) ) {
        return( -1 );
    }
    memcpy( dest, ZLOG_FMT_PLUGIN_LABEL, strlen( ZLOG_FMT_PLUGIN_LABEL ));
    return( strlen( ZLOG_FMT_PLUGIN_LABEL ));
}


/*!
 * \brief return length of formatted part of log entry
 * 
 * \param   tv              time of log entry
 * 
 * \return                  number of characters that would be inserted into destination buffer, <0: error
 */
static int zlogLength( struct timeval *tv )
{
    return( strlen( ZLOG_FMT_PLUGIN_LABEL ));
}
/*!
 * \endcond
 */
/*! @} */
