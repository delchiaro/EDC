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
 *   \brief Dump log messages kept in ring buffer to other appenders
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
 * Local function declarations
 */


/*!
 * \addtogroup xgLogger
 * @{
 */

/*!
 * \brief dump ring log buffer
 * 
 * \param   logger_id       logger reference
 * 
 * \return                  error code: 0=ok, <0=error
 */
int zlogRingDump( zlogLogger logger_id )
{
    sLogger         *pLog;
    sAppenderList   *pAppList_Ring;
    sAppenderList   *pAppList;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        return( ZLOG_E_NO_LOGGER );
    }
    
    // dump all ring buffers
    for( pAppList_Ring = pLog->appenders; pAppList_Ring != NULL; pAppList_Ring = pAppList_Ring->next ) {
        // check for ring appender
        if( strcasecmp( pAppList_Ring->appender->plugin->label, "ring:" ) != 0 ) continue;
        
        // search for appender marked as ring dump target
        for( pAppList = pLog->appenders; pAppList != NULL; pAppList = pAppList-> next ) {
            if( pAppList == pAppList_Ring ) continue;
            
            if( pAppList->ringdump == 0 ) continue;
            
            ringDump( pAppList_Ring->appender, pAppList->appender );
        }
    }
    
    return( ZLOG_NO_ERROR );
}
/*! @} */
