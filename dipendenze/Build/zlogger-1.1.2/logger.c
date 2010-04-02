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
 *   \brief Create and maintain logger
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
 * global variables
 */
int                 zlogErrno = zlogLevelNone;


/*
 * Local variables
 */
static sLogger      *listLogger = NULL;


/*!
 * \addtogroup xgLogger
 * @{
 */

/*!
 * \brief create logger
 * 
 * \param   name            name of logger, used in log statements
 * \param   levels          bitmask of levels logger acts upon
 * 
 * \return                  pointer to new logger, NULL upon error
 */
zlogLogger zlogLoggerCreate( char *name, unsigned int levels )
{
    sLogger     *pLog;
    
    // parameter sanity checks
    if( name == NULL || *name == '\0' ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( NULL );
    }
    if( levels >= 2 * zlogLevelGetTop() ) {
        zlogErrno = ZLOG_E_INVALID_LEVEL;
        return( NULL );
    }
    
    // create new logger
    if( (pLog = malloc( sizeof( sLogger ))) == NULL ) {
        zlogErrno = ZLOG_E_OUTOFMEMORY;
        return( NULL );
    }
    
    // initialise attributes
    pLog->name = strdup( name );
    pLog->levels = levels;
    pLog->appenders = NULL;
    memset( pLog->_magic, '\0', MAGIC_MAX_LENGTH );
    strncpy( pLog->_magic, MAGIC_LOGGER, MAGIC_MAX_LENGTH );
    pLog->next = listLogger;
    listLogger = pLog;
    zlogErrno = ZLOG_NO_ERROR;
    return( pLog );
}


/*!
 * \brief find logger definition by name
 * 
 * \param   name            logger name to search
 * 
 * \return                  logger reference
 */
zlogLogger zlogLoggerFind( char *name )
{
    sLogger     *pLog;
    
    for( pLog = listLogger; pLog != NULL; pLog= pLog->next ) {
        if( strcmp( pLog->name, name ) == 0 ) {
            break;
        }
    }
    zlogErrno = ZLOG_NO_ERROR;
    return( pLog );
}


/*!
 * \brief add appender to logger
 * 
 * \param   logger_id       logger reference
 * \param   appender_id     appender reference
 * \param   levels          bitmask of levels this appender acts upon
 * \param   ringdump        1: dump ring buffer messages to this appender, 0: this appender is not a dump target
 * 
 * \return                  logger reference
 */
int zlogLoggerAddAppender( zlogLogger logger_id, zlogAppender appender_id, unsigned int levels, int ringdump )
{
    sLogger         *pLog;
    sAppender       *pApp;
    sAppenderList   *pList;
    sAppenderList   *pEntry;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_LOGGER;
        return( zlogErrno );
    }
    if( (pApp = _zlogCheckAppenderID( appender_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_APPENDER;
        return( zlogErrno );
    }
    
    // add appender to this loggers appender list
    if( (pList = malloc( sizeof( sAppenderList ))) == NULL ) {
        zlogErrno = ZLOG_E_OUTOFMEMORY;
        return( zlogErrno );
    }
    pList->appender = pApp;
    pList->levels = levels;
    pList->ringdump = ringdump;
    pList->next = NULL;
    
    if( pLog->appenders == NULL ) {
        pLog->appenders = pList;
    } else {
        for( pEntry = pLog->appenders; pEntry->next != NULL; pEntry = pEntry->next )
            ;
        pEntry->next = pList;
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}


/*!
 * \brief set log level
 * 
 * \param   logger_id       logger reference
 * \param   levels          bitmask of levels logger acts upon
 * 
 * \return                  >=0: previous level, <0: error
 */
int zlogLoggerSetLevel( zlogLogger logger_id, unsigned int levels )
{
    sLogger         *pLog;
    unsigned int    previous;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_LOGGER;
        return( zlogErrno );
    } else if( levels >= 2 * zlogLevelGetTop() ) {
        zlogErrno = ZLOG_E_INVALID_LEVEL;
        return( zlogErrno );
    }
    
    previous = pLog->levels;
    pLog->levels = levels;
    
    zlogErrno = ZLOG_NO_ERROR;
    return( previous );
}


/*!
 * \brief get log level
 * 
 * \param   logger_id       logger reference
 * 
 * \return                  >=0: bitmask of levels logger acts upon, <0: error
 */
unsigned int zlogLoggerGetLevel( zlogLogger logger_id )
{
    sLogger *pLog;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_LOGGER;
        return( zlogErrno );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pLog->levels );
}


/*!
 * \brief get logger name
 * 
 * \param   logger_id       logger reference
 * 
 * \return                  pointer to logger's name, NULL on error
 */
char *zlogLoggerGetName( zlogLogger logger_id )
{
    sLogger *pLog;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) {
        zlogErrno = ZLOG_E_NO_LOGGER;
        return( NULL );
    }
    
    zlogErrno = ZLOG_NO_ERROR;
    return( pLog->name );
}


/*!
 * \cond DeveloperDocs
 */

zlogAppender zlogLoggerGetAppenderList( zlogLogger logger_id, unsigned int position )
{

    return( NULL );
}
/*!
 * \endcond
 */
/*! @} */
