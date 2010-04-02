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
 *   \brief Create and maintain log appenders
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "zlogger.private.h"


/*
 * Local variables
 */
static sAppender    *pDefaultAppender = NULL;
static sAppender    *listAppender = NULL;
static sAppenderPlugin  *appenders = NULL;


/*!
 * \addtogroup xgAppender
 * @{
 */

/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief make default appenders available to applications
 */
static void _zlogAppenderInit( void )
{
    appenders = zlogFile_Init();
    appenders->next = zlogSyslog_Init();
    appenders->next->next = zlogRing_Init();
    // appenders->next->next->next = zlogUDP_Init();
}


/*!
 * \brief load appender plugin
 * 
 * \param   pluginInit      pointer to plugin initialisation function
 * 
 * \return                  0: ok, <0: error
 */
int _zlogAppenderLoad( sAppenderPlugin *(*pluginInit)( void ) )
{
    sAppenderPlugin *pPlugin;
    sAppenderPlugin *pPrevious;
    sAppenderPlugin *pNew;
    
    // load list of built-in appenders
    if( appenders == NULL ) _zlogAppenderInit();
    
    // get plugin definition
    pNew = (*pluginInit)();
    pNew->next = NULL;
    
    // update linked-list of appenders
    pPrevious = NULL;
    for( pPlugin = appenders; pPlugin != NULL; pPlugin = pPlugin->next ) {
        if( strcasecmp( pNew->label, pPlugin->label ) == 0 ) {
            // overloading built-in appender
            break;
        }
        pPrevious = pPlugin;
    }
    if( pPlugin == NULL ) {
        // new appender, append at end of list
        if( pPrevious == NULL ) {
            // first appender on list
            appenders = pNew;
        } else {
            pPrevious->next = pNew;
        }
    } else {
        // replace previously loaded appender
        pNew->next = pPlugin->next;
        if( pPrevious != NULL ) {
            pPrevious->next = pNew;
        }
        /*
         * ATTENTION:
         * Memory of replaced pPlugin is not released!
         * Yes, this could be a memory leak. However, plugins are usually only loaded once,
         * at startup. In addition, their number is very low and limited.
         * And finally, we would have to add a flag to the plugin definition structure to
         * tell us if it is a built-in plugin whose memory is static and cannot be released.
         */
    }
    
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief define appender (internal worker function)
 * 
 * \param   name            name of appender
 * \param   plugin          pointer to plugin definition
 * \param   parameters      appender-specific parameters to establish channel
 * \param   format_id       format definition for this appender
 * 
 * \return                  pointer to new appender definition, NULL upon error
 */
static sAppender *_zlogAppenderDefine( char *name, sAppenderPlugin *plugin, char *parameters, zlogFormat format_id )
{
    sAppender   *pApp;
    sFormat     *pFmt;
    
    // parameter sanity checks
    if( name == NULL || *name == '\0' || (*plugin->check)( parameters ) != ZLOG_NO_ERROR ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( NULL );
    }
    if( (pFmt = _zlogCheckFormatID( format_id )) == NULL ) {
        pFmt = zlogFormatDefault();
    }
    
    // create new format definition
    if( (pApp = malloc( sizeof( sAppender ))) == NULL ) {
        zlogErrno = ZLOG_E_OUTOFMEMORY;
        return( NULL );
    }
    
    // initialise attributes
    pApp->name = strdup( name );
    pApp->plugin = plugin;
    pApp->parameters = strdup( parameters );
    pApp->format = pFmt;
    pApp->options = ZLOG_APP_OPT_NONE; // ZLOG_APP_OPT_NONE ZLOG_APP_OPT_DUPLICATE
    pApp->channel = NULL;
    pApp->lastMsg = NULL;
    pApp->repetitions = 0;
    memset( pApp->_magic, '\0', MAGIC_MAX_LENGTH );
    
    // open channel
    if( (*plugin->open)( pApp ) != ZLOG_E_NO_ERROR ) {
        zlogErrno = ZLOG_E_CHANNEL;
        free( pApp->parameters );
        free( pApp->name );
        free( pApp );
        return( NULL );
    }
    
    // add to appender list
    strncpy( pApp->_magic, MAGIC_APPENDER, MAGIC_MAX_LENGTH );
    pApp->next = listAppender;
    listAppender = pApp;
    
    // default appender is always first defined appender
    if( pDefaultAppender == NULL ) {
        pDefaultAppender = pApp;
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pApp );
}

/*!
 * \endcond
 */


/*!
 * \brief define appender
 * 
 * \param   name            name of appender
 * \param   type            type of appender, e.g. file:, syslog:, null:, etc            
 * \param   parameters      type-specific parameters, such as filename, syslog facility, etc.
 * \param   format_id       format definition for this appender
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
zlogAppender zlogAppenderDefine( char *name, char *type, char *parameters, zlogFormat format_id )
{
    sAppenderPlugin     *pPlugin;
    
    if( appenders == NULL ) _zlogAppenderInit();
    
    for( pPlugin = appenders; pPlugin != NULL; pPlugin = pPlugin->next ) {
        if( strcasecmp( type, pPlugin->label ) == 0 ) {
            return( _zlogAppenderDefine( name, pPlugin, parameters, format_id ));
        }
    }
    
    zlogErrno = ZLOG_E_APPENDER_NOTFOUND;
    return( NULL );
}


/*!
 * \brief simple appender definition
 * 
 * \param   name            name of appender
 * \param   params          appender definition parameters, format: type:destination      
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
zlogAppender zlogAppenderSimple( char *name, char *params )
{
    sAppenderPlugin     *pPlugin;
    
    if( appenders == NULL ) _zlogAppenderInit();
    if( params == NULL ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( NULL );
    }
    
    for( pPlugin = appenders; pPlugin != NULL; pPlugin = pPlugin->next ) {
        if( strncasecmp( params, pPlugin->label, strlen( pPlugin->label )) == 0 ) {
            return( _zlogAppenderDefine( name, pPlugin, &params[strlen( pPlugin->label )], NULL ));
        }
    }
    
    zlogErrno = ZLOG_E_APPENDER_NOTFOUND;
    return( NULL );
}


/*!
 * \brief find appender definition by name
 * 
 * \param   name            appender name to search
 * 
 * \return                  appender reference
 */
zlogAppender zlogAppenderFind( char *name )
{
    sAppender   *pApp;
    
    for( pApp = listAppender; pApp != NULL; pApp= pApp->next ) {
        if( strcmp( pApp->name, name ) == 0 ) {
            break;
        }
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pApp );
}


/*!
 * \brief return default appender
 * 
 * \return                  pointer to default appender, NULL upon error
 */
zlogAppender zlogAppenderGetDefault( void )
{
    zlogErrno = ZLOG_NO_ERROR;
    return( pDefaultAppender );
}


/*!
 * \brief set default appender
 * 
 * \param   appender_id     reference of new default appender
 * 
 * \return                  pointer to default appender, NULL upon error
 */
int zlogAppenderSetDefault( zlogAppender appender_id )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( zlogErrno );
    }
    
    pDefaultAppender = pApp;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}


/*!
 * \brief get format definition
 * 
 * \param   appender_id     appender reference
 * 
 * \return                  appender string
 */
zlogFormat zlogAppenderGetFormat( zlogAppender appender_id )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( NULL );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pApp->format );
}


/*!
 * \brief set format definition
 * 
 * \param   appender_id     appender definition
 * \param   format_id       format definition
 * 
 * \return                  0: ok, <0: error
 */
int zlogAppenderSetFormat( zlogAppender appender_id, zlogFormat format_id )
{
    sAppender   *pApp;
    sFormat     *pFmt;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( zlogErrno );
    } else if( (pFmt = _zlogCheckFormatID( format_id )) == NULL ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( zlogErrno );
    }
    
    pApp->format = pFmt;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}


/*!
 * \brief get parameters
 * 
 * \param   appender_id     appender reference
 * 
 * \return                  parameter string
 */
char *zlogAppenderGetParameters( zlogAppender appender_id )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( NULL );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pApp->parameters );
}


/*!
 * \brief set parameters
 * 
 * \param   appender_id     appender reference
 * \param   params          appender-specific parameters, such as filename or syslog facility
 * 
 * \return                  0: ok, <0: error
 */
int zlogAppenderSetParameters( zlogAppender appender_id, void *params )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( zlogErrno );
    }
    
    pApp->parameters = (char *)params;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}


/*!
 * \brief get option settings
 * 
 * \param   appender_id     appender reference
 * 
 * \return                  option settings or -1: error
 */
int zlogAppenderGetOptions( zlogAppender appender_id )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( -1 );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pApp->options );
}


/*!
 * \brief set options
 * 
 * \param   appender_id     appender definition
 * \param   options         option settings
 * 
 * \return                  0: ok, <0: error
 */
int zlogAppenderSetOptions( zlogAppender appender_id, int options )
{
    sAppender   *pApp;
    
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( zlogErrno );
    }
    
    pApp->options = options;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}
/*! @} */
