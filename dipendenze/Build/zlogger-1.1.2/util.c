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
 *   \brief Utility functions
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "zlogger.private.h"

/*!
 * \addtogroup xgUtil
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

/*!
 * check logger id validity
 * 
 * \param   pLog            pointer to a logger as returned by zlogLoggerCreate() or zlogLoggerFind()
 * 
 * \return                  0: valid pointer, <0: invalid structure
 */
sLogger * _zlogCheckLoggerID( zlogLogger logger_id )
{
    sLogger     *pLog;
    
    pLog = (sLogger *) logger_id;
    
    if( pLog == NULL ) {
        return( NULL );
    } else if( strcmp( pLog->_magic, MAGIC_LOGGER ) != 0 ) {
        return( NULL );
    }
    return( pLog );
}


/*!
 * check format id validity
 * 
 * \param   pFmt            pointer to a format definition as returned by zlogFormatDefine() or zlogFormatFind()
 * 
 * \return                  0: valid pointer, <0: invalid structure
 */
sFormat * _zlogCheckFormatID( zlogFormat format_id )
{
    sFormat     *pFmt;
    
    pFmt = (sFormat *) format_id;
    
    if( pFmt == NULL ) {
        return( NULL );
    } else if( strcmp( pFmt->_magic, MAGIC_FORMAT ) != 0 ) {
        return( NULL );
    }
    return( pFmt );
}


/*!
 * check appender id validity
 * 
 * \param   pApp            pointer to a appender as returned by zlogAppenderDefine() or zlogAppenderFind()
 * 
 * \return                  0: valid pointer, <0: invalid structure
 */
sAppender * _zlogCheckAppenderID( zlogAppender appender_id )
{
    sAppender   *pApp;
    
    pApp = (sAppender *) appender_id;
    
    if( pApp == NULL ) {
        return( NULL );
    } else if( strcmp( pApp->_magic, MAGIC_APPENDER ) != 0 ) {
        return( NULL );
    }
    return( pApp );
}
/*!
 * \endcond
 */
/*! @} */
