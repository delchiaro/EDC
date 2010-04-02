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
 *   \brief Plugin management
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


/*!
 * \addtogroup xgPlugin
 * @{
 */

/*!
 * \brief load plugin
 * 
 * \param   path            pathname of shared library containing plugin
 * 
 * \return                  0: ok, <0: error
 */
char *zlogPluginLoad( char *path )
{
    void            *handle;
    eZLogPluginType (*pluginType)( void );
    void            *(*pluginInit)( void );
    char            *errmsg;
    
    // open plugin
    handle = dlopen( path, RTLD_NOW + RTLD_LOCAL );
    if( handle == NULL ) {
        zlogErrno = ZLOG_E_PLUGIN_OPEN;
        return( strdup( dlerror() ));
    }
    
    // get pointer to well-known functions
    //  - zlogPlugin_GetType()
    //  - zlogPlugin_Init()
    dlerror();  // clear any outstanding error conditions
    pluginType = dlsym( handle, "zlogPlugin_GetType" );
    if( ( errmsg = dlerror()) != NULL ) {
        // couldn't find symbol
        errmsg = strdup( errmsg );
        dlclose( handle );
        zlogErrno = ZLOG_E_PLUGIN_SYMBOL;
        return( errmsg );
    }
    pluginInit = dlsym( handle, "zlogPlugin_Init" );
    if( ( errmsg = dlerror()) != NULL ) {
        // couldn't find symbol
        errmsg = strdup( errmsg );
        dlclose( handle );
        zlogErrno = ZLOG_E_PLUGIN_SYMBOL;
        return( errmsg );
    }
    
    switch( (*pluginType)() ) {
        case zlogPluginAppender:
            _zlogAppenderLoad( (sAppenderPlugin *(*)( void )) pluginInit );
            break;
        case zlogPluginFormat:
            _zlogFormatLoad( (sFormatPlugin *(*)( void )) pluginInit );
            break;
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( NULL );
}


/*!
 * \brief return default plugin directory
 */
char *zlogPluginDir( void )
{
    return( PLUGIN_DIR );
}
/*! @} */
