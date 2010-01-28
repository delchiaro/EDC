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
 *   \brief Create and maintain log formats
 * \endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlogger.private.h"


/*
 * Local variables
 */
static sFormat          *listFormat = NULL;
static sFormatPlugin    *formatPlugins = NULL;


/*!
 * \addtogroup xgFormat
 * @{
 */

/*
 * built-in format string placeholders
 */
/*
 * %d   short date (e.g. 22/11/2008)
 * %D   long date (e.g., 22 November 2008)
 * %t   short time (e.g. 14:18:52)
 * %T   long time (e.g. 14:18:52.082)
 * %r   short relative time (e.g. 00:00:01.983)
 * %R   long relative time (e.g. 0d 00:00:01.983)
 * %m   message
 * %M   message id
 * %l   level code
 * %L   level text
 * %n   name of logger
 * %%   single percent sign
 */


/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief load format plugin
 * 
 * \param   pluginInit      pointer to plugin initialisation function
 * 
 * \return                  0: ok, <0: error
 */
int _zlogFormatLoad( sFormatPlugin *(*pluginInit)( void ) )
{
    sFormatPlugin *pNew;
    
    // get plugin definition
    pNew = (*pluginInit)();
    pNew->next = formatPlugins;
    formatPlugins = pNew;
    
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief call plugin to return formatted part of log message
 * 
 * \param   placeholder     placeholder character found in format string
 * \param   dest            buffer receiving formatted result
 * \param   maxlen          maximum size of buffer
 * \param   tv              current time, can be used to provide different date/time formats
 * 
 * \return                  >=0: number of characters put in buffer, <0: error
 */
int _zlogFormatPluginPrintf( char placeholder, char *dest, int maxlen, struct timeval *tv )
{
    sFormatPlugin   *pPlugin;
    
    for( pPlugin = formatPlugins; pPlugin != NULL; pPlugin = pPlugin->next ) {
        if( pPlugin->placeholder == placeholder ) {
            return( (*pPlugin->printf)( dest, maxlen, tv ) );
        }
    }
    return( -1 );
}


/*!
 * \brief call plugin to get length of formatted part of log message
 * 
 * \param   placeholder     placeholder character found in format string
 * \param   tv              current time, can be used to provide different date/time formats
 * 
 * \return                  >=0: length, <0: error
 */
int _zlogFormatPluginLength( char placeholder, struct timeval *tv )
{
    sFormatPlugin   *pPlugin;
    
    for( pPlugin = formatPlugins; pPlugin != NULL; pPlugin = pPlugin->next ) {
        if( pPlugin->placeholder == placeholder ) {
            return( (*pPlugin->len)( tv ) );
        }
    }
    return( -1 );
}

/*!
 * \endcond
 */


/*!
 * \brief return default format
 * 
 * \return                  pointer to default format definition
 */
zlogFormat zlogFormatDefault( void )
{
    static sFormat  *pFmt = NULL;
    
    if( pFmt == NULL ) {
        pFmt = zlogFormatDefine( "__default__", "%d %T - %L - %M - %n - %m" );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pFmt );
}


/*!
 * \brief create format
 * 
 * \param   name            name of format
 * \param   format          format string
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
zlogFormat zlogFormatDefine( char *name, char *format )
{
    sFormat     *pFmt;
    
    // parameter sanity checks
    if( name == NULL || *name == '\0' || format == NULL || *format == '\0' ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( NULL );
    }
    
    // create new format definition
    if( (pFmt = malloc( sizeof( sFormat ))) == NULL ) {
        zlogErrno = ZLOG_E_OUTOFMEMORY;
        return( NULL );
    }
    
    // initialise attributes
    pFmt->name = strdup( name );
    pFmt->format = strdup( format );
    memset( pFmt->_magic, '\0', MAGIC_MAX_LENGTH );
    strncpy( pFmt->_magic, MAGIC_FORMAT, MAGIC_MAX_LENGTH );
    pFmt->next = listFormat;
    listFormat = pFmt;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pFmt );
}


/*!
 * \brief find format definition by name
 * 
 * \param   name            format name to search
 * 
 * \return                  format reference
 */
zlogFormat zlogFormatFind( char *name )
{
    sFormat *pFmt;
    
    for( pFmt = listFormat; pFmt != NULL; pFmt= pFmt->next ) {
        if( strcmp( pFmt->name, name ) == 0 ) {
            break;
        }
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pFmt );
}


/*!
 * \brief get log format string
 * 
 * \param   format_id       format reference
 * 
 * \return                  format string
 */
char *zlogFormatGetFormat( zlogFormat format_id )
{
    sFormat     *pFmt;
    
    if( (pFmt = _zlogCheckFormatID( format_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_FORMAT;
        return( NULL );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pFmt->format );
}
/*! @} */
