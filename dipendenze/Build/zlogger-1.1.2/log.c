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
 *   \brief Log messages
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "zlogger.private.h"


/*
 * Local function declarations
 */
static void     _zlogPrintf( char *buf, int maxlen, char *format, char *modulename, unsigned int level, int level_idx, int msgid, char *message );
static int      _zlogPrintfGetLen( char *format, char *modulename, unsigned int level, int level_idx, int msgid, char *message );
// static int      round_double( double real );
static int      bit_number( unsigned int number );
static int      digits( unsigned int number );


/*!
 * \addtogroup xgLogger
 * @{
 */

/*
 * levels
 * - 32 level names
 * - one per bit in unsigned integer
 * - the first 7 are standard
 * - the remaining 25 can be defined individually by each application
 */
static char *levelNames[] = {
    "INF",
    "INF",      // verbose
    "WRN",
    "ERR",
    "CRT",
    "FAT",
    "USR",
    "DEB",
    "TRC",
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL
};
#define ZLOG_UNKNOWN_LEVEL_NAME     "UNK"
#define ZLOG_STANDARD_LEVELS        9

static char *monthNames[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

static unsigned int topLevel = zlogLevelTrace;


/*!
 * \brief define additional logging level
 * 
 * \param   level           id for this log level (number must a power of 2)
 * \param   name            level name used in log lines
 * 
 * \return                  0: ok, <0: error
 */
int zlogLevelSetName( unsigned int level, char *name )
{
    int     level_idx;
    
    level_idx = bit_number( level );
    if( level != topLevel * 2 || level_idx < ZLOG_STANDARD_LEVELS ) {
        zlogErrno = ZLOG_E_PARAMETERS;
        return( zlogErrno );
    }
    if( levelNames[level_idx] != NULL ) {
        free( levelNames[level_idx] );
    }
    levelNames[level_idx] = strdup( name );
    topLevel = level;
    zlogErrno = ZLOG_NO_ERROR;
    return( zlogErrno );
}


/*!
 * \brief return highest defined logging level
 * 
 * \return                  >0: highest defined logging level, <0: error
 */
unsigned int zlogLevelGetTop( void )
{
    return( topLevel );
}


/*!
 * \brief log a message
 * 
 * The message buffer is pre-allocated. It supports messages up to 1023 characters.
 * 
 * \param   logger_id       logger reference
 * \param   level           log level for this message
 * \param   msgid           unique message id
 * \param   message         printf-compatible message with parameters
 */
void zlog( zlogLogger logger_id, unsigned int level, int msgid, char *message, ... )
{
    va_list         ap;
    
    va_start( ap, message );
    zlogv( logger_id, level, msgid, message, ap );
    va_end( ap );
}


/*!
 * \brief log a message va_list version for varargs passing
 * 
 * The message buffer is pre-allocated. It supports messages up to 1023 characters.
 * 
 * \param   logger_id       logger reference
 * \param   level           log level for this message
 * \param   msgid           unique message id
 * \param   message         printf-compatible message with parameters
 * \param   ap              pointer to list of variable number arguments, as required by 'message'
 */
void zlogv( zlogLogger logger_id, unsigned int level, int msgid, char *message, va_list ap )
{
    sLogger         *pLog;
    sAppenderList   *pAppList;
    char            msg[1024];
    char            entry[ZLOG_MAX_MSG_SIZE];
    int             level_idx;
    int             print_entry = 1;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) return;
    
    if( (level & pLog->levels) == 0 ) return;
    
    vsnprintf( entry, ZLOG_MAX_MSG_SIZE, message, ap );
    
    // compute level index only once
    level_idx = bit_number( level ); // round_double( log( level ) / log( 2 ) );

    for( pAppList = pLog->appenders; pAppList != NULL; pAppList = pAppList->next ) {
        // check if appender is active for current level
        if( (level & pAppList->levels) == 0 ) continue;
        
        // de-duplicate if required
        if( pAppList->appender->options & ZLOG_APP_OPT_DUPLICATE ) {
            if( pAppList->appender->lastMsg == NULL ) {
                pAppList->appender->repetitions = 1;
                pAppList->appender->lastMsg = strdup( entry );
                pAppList->appender->lastLevel = level;
                pAppList->appender->lastLevelIndex = level_idx;
                pAppList->appender->lastMsgId = msgid;
            } else if( strcmp( pAppList->appender->lastMsg, entry ) == 0 ) {
                pAppList->appender->repetitions++;
                print_entry = 0;
            } else {
                char    dupMsg[ZLOG_MAX_MSG_SIZE];
                
                // print message if duplicate entries have been removed
                free( pAppList->appender->lastMsg );
                pAppList->appender->lastMsg = strdup( entry );
                snprintf( dupMsg, ZLOG_MAX_MSG_SIZE, "Last log entry repeated %d times", pAppList->appender->repetitions );
                _zlogPrintf( msg, 1024, pAppList->appender->format->format, pLog->name,
                             pAppList->appender->lastLevel, pAppList->appender->lastLevelIndex, pAppList->appender->lastMsgId,
                             dupMsg );
                if( pAppList->appender->channel == NULL ) {
                    (*pAppList->appender->plugin->open)( pAppList->appender );
                }
                if( pAppList->appender->channel != NULL ) {
                    (*pAppList->appender->plugin->log)( pAppList->appender, level_idx, msg );
                }
                pAppList->appender->repetitions = 1;
                pAppList->appender->lastLevel = level;
                pAppList->appender->lastLevelIndex = level_idx;
                pAppList->appender->lastMsgId = msgid;
            }
        }
        
        if( print_entry != 0 ) {
            // create log entry from format
            _zlogPrintf( msg, 1024, pAppList->appender->format->format, pLog->name, level, level_idx, msgid, entry );
            
            // if required, open log channel
            if( pAppList->appender->channel == NULL ) {
                (*pAppList->appender->plugin->open)( pAppList->appender );
            }
            
            // send message to log channel
            if( pAppList->appender->channel != NULL ) {
                (*pAppList->appender->plugin->log)( pAppList->appender, level_idx, msg );
            }
        }
    }
}


/*!
 * \brief log a message, dynamically allocating memory as required
 * 
 * This version generally should use less memory than its standard counterpart zlog().
 * In addition, there's no limit to the message length.
 * However, due to pre-calculating the message length and dynamically allocating/freeing
 * memory, it is also slower. 
 * 
 * \param   logger_id       logger reference
 * \param   level           log level for this message
 * \param   msgid           unique message id
 * \param   message         printf-compatible message with parameters
 */
void zlog_dynmem( zlogLogger logger_id, unsigned int level, int msgid, char *message, ... )
{
    va_list         ap;
    
    va_start( ap, message );
    zlog_dynmemv( logger_id, level, msgid, message, ap );
    va_end( ap );
}


/*!
 * \brief log a message, dynamically allocating memory, va_list version for varargs passing
 * 
 * This version generally should use less memory than its standard counterpart zlog().
 * In addition, there's no limit to the message length.
 * However, due to pre-calculating the message length and dynamically allocating/freeing
 * memory, it is also slower. 
 * 
 * \param   logger_id       logger reference
 * \param   level           log level for this message
 * \param   msgid           unique message id
 * \param   message         printf-compatible message with parameters
 * \param   ap              pointer to list of variable number arguments, as required by 'message'
 */
void zlog_dynmemv( zlogLogger logger_id, unsigned int level, int msgid, char *message, va_list ap )
{
    sLogger         *pLog;
    sAppenderList   *pAppList;
    char            *msg;
    char            entry[ZLOG_MAX_MSG_SIZE];
    int             level_idx;
    int             bufsize;
    int             print_entry = 1;
    
    if( (pLog = _zlogCheckLoggerID( logger_id )) == NULL ) return;
    
    if( (level & pLog->levels) == 0 ) return;
    
    vsnprintf( entry, ZLOG_MAX_MSG_SIZE, message, ap );
    
    // compute level index only once
    level_idx = bit_number( level ); // round_double( log( level ) / log( 2 ) );
    
    for( pAppList = pLog->appenders; pAppList != NULL; pAppList = pAppList->next ) {
        // check if appender is active for current level
        if( (level & pAppList->levels) == 0 ) return;
        
        // de-duplicate if required
        if( pAppList->appender->options & ZLOG_APP_OPT_DUPLICATE ) {
            if( pAppList->appender->lastMsg == NULL ) {
                pAppList->appender->repetitions++;
                pAppList->appender->lastMsg = strdup( entry );
                pAppList->appender->lastLevel = level;
                pAppList->appender->lastLevelIndex = level_idx;
                pAppList->appender->lastMsgId = msgid;
            } else if( strcmp( pAppList->appender->lastMsg, entry ) == 0 ) {
                pAppList->appender->repetitions++;
                print_entry = 0;
            } else {
                char    dupMsg[ZLOG_MAX_MSG_SIZE];
                
                free( pAppList->appender->lastMsg );
                pAppList->appender->lastMsg = strdup( entry );
                snprintf( dupMsg, ZLOG_MAX_MSG_SIZE, "Last log entry repeated %d times", pAppList->appender->repetitions );
                bufsize = _zlogPrintfGetLen( pAppList->appender->format->format, pLog->name,
                                             pAppList->appender->lastLevel, pAppList->appender->lastLevelIndex, pAppList->appender->lastMsgId,
                                             dupMsg );
                msg = malloc( bufsize );
                if( msg != NULL ) {
                    _zlogPrintf( msg, 1024, pAppList->appender->format->format, pLog->name,
                                 pAppList->appender->lastLevel, pAppList->appender->lastLevelIndex, pAppList->appender->lastMsgId,
                                 dupMsg );
                    if( pAppList->appender->channel == NULL ) {
                        (*pAppList->appender->plugin->open)( pAppList->appender );
                    }
                    if( pAppList->appender->channel != NULL ) {
                        (*pAppList->appender->plugin->log)( pAppList->appender, level_idx, msg );
                    }
                    free( msg );
                }
                pAppList->appender->repetitions = 1;
                pAppList->appender->lastLevel = level;
                pAppList->appender->lastLevelIndex = level_idx;
                pAppList->appender->lastMsgId = msgid;
            }
        }
        
        if( print_entry != 0 ) {
            // create log entry from format
            bufsize = _zlogPrintfGetLen( pAppList->appender->format->format, pLog->name, level, level_idx, msgid, entry );
            msg = malloc( bufsize );
            if( msg == NULL ) return;
            _zlogPrintf( msg, bufsize, pAppList->appender->format->format, pLog->name, level, level_idx, msgid, entry );
            
            // if required, open log channel
            if( pAppList->appender->channel == NULL ) {
                (*pAppList->appender->plugin->open)( pAppList->appender );
            }
            
            // send message to log channel
            if( pAppList->appender->channel != NULL ) {
                (*pAppList->appender->plugin->log)( pAppList->appender, level_idx, msg );
            }
            free( msg );
        }
    }
}


/*!
 * \cond DeveloperDocs
 */
/*
 * %d   short date (e.g. 22/11/2008)
 * %D   long date (e.g. 22 November 2008)
 * %t   short time (e.g. 14:18:52)
 * %T   long time (e.g. 14:18:52.082)
 * %r   short relative time (e.g. 00:00:01.983)
 * %R   long relative time (e.g. 0d 00:00:01.983)
 * %m   message
 * %M   message id
 * %l   level code (e.g. 3)
 * %L   level text (e.g. WRN)
 * %n   name of logger (e.g. Database)
 * %%   single percent sign
 */
static void _zlogPrintf( char *buf, int maxlen, char *format, char *modulename, unsigned int level, int level_idx, int msgid, char *message )
{
    int             len;
    char            *src;
    char            *ptr;
    char            *end;
    struct timeval  tv;
    struct tm       *ltime = NULL;
    
    gettimeofday( &tv, NULL );
    ltime = localtime( &tv.tv_sec );
    ptr = buf;
    src = format;
    end = &buf[maxlen -1];      // terminating '\0'
    while( *src != '\0' && ptr < end ) {
        if( *src != '%' ) {
            *ptr = *src;
            ptr++;
            src++;
            continue;
        }
        src++;
        /*
         * ATTENTION: could result in buffer overflows
         */
        switch( *src ) {
            case 'd':
                len = snprintf( ptr, 11, "%04d/%02d/%02d", ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday );
                break;
            case 'D':
                len = sprintf( ptr, "%d %s %04d", ltime->tm_mday, monthNames[ltime->tm_mon], ltime->tm_year + 1900 );
                break;
            case 't':
                len = snprintf( ptr, 9, "%02d:%02d:%02d", ltime->tm_hour, ltime->tm_min, ltime->tm_sec );
                break;
            case 'T':
                len = snprintf( ptr, 13, "%02d:%02d:%02d.%03d", ltime->tm_hour, ltime->tm_min, ltime->tm_sec, (uint32_t)tv.tv_usec / 1000 );
                break;
            case 'r':
            case 'R':
                strcpy( ptr, "<not implemented>" );
                len = strlen( "<not implemented>" );
                break;
            case 'm':
                strcpy( ptr, message );
                len = strlen( message );
                break;
            case 'M':
                len = sprintf( ptr, "%d", msgid );
                break;
            case 'l':
                len = sprintf( ptr, "%d", level );
                break;
            case 'L':
                if( levelNames[level_idx] != NULL ) {
                    strcpy( ptr, levelNames[level_idx] );
                    len = strlen( levelNames[level_idx] );
                } else {
                    strcpy( ptr, ZLOG_UNKNOWN_LEVEL_NAME );
                    len = strlen( ZLOG_UNKNOWN_LEVEL_NAME );
                }
                break;
            case 'n':
                strcpy( ptr, modulename );
                len = strlen( modulename );
                break;
            case '%':
            default:
                if( (len = _zlogFormatPluginPrintf( *src, ptr, end - ptr, &tv )) < 0 ) {
                    *ptr = *src;
                    len = 1;
                }
                break;
        }
        ptr += len;
        src++;
    }
        *ptr = '\0';
}


static int _zlogPrintfGetLen( char *format, char *modulename, unsigned int level, int level_idx, int msgid, char *message )
{
    int             len;
    int             tmp;
    char            *src;
    char            *ptr;
    char            item_D[128];
    char            item_R[128];
    struct timeval  tv;
    struct tm       *ltime = NULL;
    
    // calculate length of message buffer
    len = 1;    // terminating '\0'
    src = format;
    for( ptr = strchr( src, '%' ); ptr != NULL; ptr = strchr( src, '%' )) {
        len += (ptr - src);
        ptr++;
        switch( *ptr ) {
            case 'd':
                if( ltime == NULL ) {
                    gettimeofday( &tv, NULL );
                    ltime = localtime( &tv.tv_sec );
                }
                len += 10;
                break;
            case 'D':
                if( ltime == NULL ) {
                    gettimeofday( &tv, NULL );
                    ltime = localtime( &tv.tv_sec );
                }
                sprintf( item_D, "%d %s %04d", ltime->tm_mday, monthNames[ltime->tm_mon], ltime->tm_year + 1900 );
                len += strlen( item_D );
                break;
            case 't':
                if( ltime == NULL ) {
                    gettimeofday( &tv, NULL );
                    ltime = localtime( &tv.tv_sec );
                }
                len += 8;
                break;
            case 'T':
                if( ltime == NULL ) {
                    gettimeofday( &tv, NULL );
                    ltime = localtime( &tv.tv_sec );
                }
                len += 12;
                break;
            case 'r':
                strcpy( item_R, "<not implemented>" );
                len += strlen( item_R );
                break;
            case 'R':
                if( ltime == NULL ) {
                    gettimeofday( &tv, NULL );
                    ltime = localtime( &tv.tv_sec );
                }
                strcpy( item_R, "<not implemented>" );
                len += strlen( item_R );
                break;
            case 'm':
                len *= strlen( message );
                break;
            case 'M':
                len += digits( msgid ); // floor( log( msgid ) / log( 10 ) );
                break;
            case 'l':
                len += digits( level ); // floor( log( level ) / log( 10 ) );
                break;
            case 'L':
                if( levelNames[level_idx] != NULL ) {
                    len += strlen( levelNames[level_idx] );
                } else {
                    len += strlen( ZLOG_UNKNOWN_LEVEL_NAME );
                }
                break;
            case 'n':
                len += strlen( modulename );
                break;
            case '%':
            default:
                if( (tmp = _zlogFormatPluginLength( *ptr, &tv )) < 0 ) {
                    len++;
                } else {
                    len += tmp;
                }
                break;
        }
        ptr++;
        src = ptr;
    }
    len += strlen( src );
    
    return( len );
}


/*!
 * \brief Get number of rightmost set bit
 * 
 * \param       number                  integer
 * 
 * \return                              number of rightmost set bit (0-7)
 */
static int bit_number( unsigned int number )
{
    int     result;
    
    for( result = 0; result < sizeof( number ) * 8; result++ ) {
        if( number & 0x01 ) {
            // rightmost bit is set - return number of right shifts
            return( result );
        }
        number >>= 1;
    }
    
    return( 0 );    // obviously, this is not correct but done this way to avoid invalid array indices
}


/*!
 * \brief Get number of digits in decimal number
 * 
 * \param       number                  integer
 * 
 * \return                              number of digits
 */
static int digits( unsigned int number )
{
    if( number > 999999999 ) return( 10 );
    else if( number > 99999999 ) return( 9 );
    else if( number > 9999999 ) return( 8 );
    else if( number > 999999 ) return( 7 );
    else if( number > 99999 ) return( 6 );
    else if( number > 9999 ) return( 5 );
    else if( number > 999 ) return( 4 );
    else if( number > 99 ) return( 3 );
    else if( number > 9 ) return( 2 );
    return( 1 );
}
/*!
 * \endcond
 */
/*! @} */
