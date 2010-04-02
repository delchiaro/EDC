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
 *   \brief Library-private definitions and structures
 * \endif
 */
 
#ifndef LOGINTERNAL_H_
#define LOGINTERNAL_H_

/*!
 * \cond DeveloperDocs
 */

#include "zlogger.h"

#define MAGIC_MAX_LENGTH    8
#define ZLOG_MAX_MSG_SIZE   512


/*
 * appender types
 */
typedef enum _eAppenderType {
    zlogAppTypeFile,
    zlogAppTypeSyslog,
    zlogAppTypeUDP,
    zlogAppTypeNull,
    zlogAppTypeRing,
} eAppenderType;


/*
 * data structures
 */
typedef struct _sFormat {
    char            _magic[MAGIC_MAX_LENGTH];
    char            *name;              //!< id of format definition
    char            *format;            //!< format template
    struct _sFormat *next;
} sFormat;

typedef struct _sAppender {
    char            _magic[MAGIC_MAX_LENGTH];
    char            *name;              //!< id of appender definition
    char            *parameters;
    int             options;            //!< which optional features have been selected
    sFormat         *format;            //!< format definition
    void            *channel;           //!< channel to write log entry to (e.g. file pointer)
    char            *lastMsg;           //!< last entry created on this appender, used to de-duplicate
    unsigned int    lastLevel;          //!< log level of last entry when de-duplicating
    int             lastLevelIndex;     //!< log level index of last entry when de-duplicating
    unsigned int    lastMsgId;          //!< message id of last entry when de-duplicating
    int             repetitions;        //!< number of times last message was repeated
    struct _sAppender *next;
    struct _sAppenderPlugin *plugin;    //!< plugin definition for this appender
} sAppender;

typedef struct _sAppenderList {
    sAppender       *appender;
    unsigned int    levels;             //!< log levels appender is active for
    int             ringdump;           //!< 1: dump ring buffer to this appender, 0: don't
    struct _sAppenderList   *next;
} sAppenderList;

typedef struct _sLogger {
    char            _magic[MAGIC_MAX_LENGTH];
    char            *name;              //!< id of logger, used as module name in log entries
    unsigned int    levels;             //!< active log levels
    sAppenderList   *appenders;         //!< linked list of appenders
    int             flags;              //!< option settings
    struct _sLogger *next;
} sLogger;

typedef struct _sAppenderPlugin {
    char            *label;
    char            *paramscan;         // ???
    int             (*open)( sAppender *pApp );
    int             (*close)( sAppender *pApp );
    int             (*log)( sAppender *pApp, unsigned int level, char *message );
    int             (*check)( char *params );
    struct _sAppenderPlugin *next;
} sAppenderPlugin;

typedef struct _sFormatPlugin {
    char            placeholder;
    int             (*printf)( char *dest, int maxlen, struct timeval *tv );
    int             (*len)( struct timeval *tv );
    struct _sFormatPlugin *next;
} sFormatPlugin;


/*
 * constants
 */
#define TRACE_MAX_MSG_SIZE       768
#define TRACE_MAX_LOG_BUFFERS      5

#define LOGGER_FLAGS_MEMOPT        1        // optimize memory usage, runs slower

#define MAGIC_MAX_LENGTH        8
#define MAGIC_LOGGER            "ZLOGGER"
#define MAGIC_APPENDER          "ZAPPEND"
#define MAGIC_FORMAT            "ZFORMAT"
#define MAGIC_RING              "ZLOGRING"


/*
 * global variables
 */


/*
 * function declarations
 */
extern sLogger          * _zlogCheckLoggerID( zlogLogger logger_id );
extern sFormat          * _zlogCheckFormatID( zlogFormat format_id );
extern sAppender        * _zlogCheckAppenderID( zlogAppender appender_id );
extern int                _zlogAppenderLoad( sAppenderPlugin *(*pluginInit)( void ) );
extern int                _zlogFormatLoad( sFormatPlugin *(*pluginInit)( void ) );
extern int                _zlogFormatPluginPrintf( char placeholder, char *dest, int maxlen, struct timeval *tv );
extern int                _zlogFormatPluginLength( char placeholder, struct timeval *tv );
extern sAppenderPlugin  * zlogFile_Init( void );
extern sAppenderPlugin  * zlogRing_Init( void );
extern sAppenderPlugin  * zlogSyslog_Init( void );
extern sAppenderPlugin  * zlogUDP_Init( void );
extern sAppenderPlugin  * zlogNull_Init( void );
extern void               ringDump( sAppender *aRing, sAppender *aOut );

/*!
 * \endcond
 */
#endif /*LOGINTERNAL_H_*/
