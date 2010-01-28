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
 *   \brief Dump logger definition structure - for debugging purposes
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "zlogger.private.h"


/*
 * Local function declarations
 */

/*!
 * \addtogroup xgLogger
 * @{
 */


/*!
 * \brief dump logger definition structure to stderr
 * 
 * \param   logger_id       logger reference
 * 
 * \return                  error code: 0=ok, <0=error
 */
int zlogDumpStructures( zlogLogger logger_id )
{
    sLogger         *pLog;
    sAppenderList   *pAppList;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        return( ZLOG_E_NO_LOGGER );
    }
    
    // dump logger structure
    fprintf( stderr, "Logger %s\n", pLog->name );
    fprintf( stderr, "  Levels: 0x%x\n", pLog->levels );
    fprintf( stderr, "  Flags:  0x%x\n", pLog->flags );
    fprintf( stderr, "  Appenders\n" );
    
    for( pAppList = pLog->appenders; pAppList != NULL; pAppList = pAppList->next ) {
        fprintf( stderr, "    %s: Levels 0x%x, dumptarget: %s\n", pAppList->appender->name, pAppList->levels, (pAppList->ringdump == 0) ? "no" : "yes" );
        fprintf( stderr, "      Type: %s\n", pAppList->appender->plugin->label );
        fprintf( stderr, "      Params: %s\n", pAppList->appender->parameters );
        fprintf( stderr, "      Options: 0x%x\n", pAppList->appender->options );
        fprintf( stderr, "      Format: %s\n", pAppList->appender->format->format );
    }
    
    return( ZLOG_NO_ERROR );
}
/*! @} */
