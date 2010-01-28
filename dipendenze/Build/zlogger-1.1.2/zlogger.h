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
 *   \brief Public defines, structures, function declarations
 * \endif
 */
 
#ifndef ZLOGGER_H_
#define ZLOGGER_H_

#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>


/*
 * \brief error constants
 */
#define ZLOG_NO_ERROR                 0             //!< Everything ok
#define ZLOG_E_NO_ERROR               0             //!< Everything ok
#define ZLOG_E_PARAMETERS            -1             //!< Invalid parameters
#define ZLOG_E_OUTOFMEMORY           -2             //!< Out of memory condition
#define ZLOG_E_NO_LOGGER             -3             //!< Invalid logger id
#define ZLOG_E_NO_FORMAT             -4             //!< Invalid format id
#define ZLOG_E_NO_APPENDER           -5             //!< Invalid appender id
#define ZLOG_E_CHANNEL               -6             //!< Problem writing data to log channel
#define ZLOG_E_SYSLOG                -7             //!< Invalid syslog facility
#define ZLOG_E_PLUGIN_OPEN           -8             //!< Unable to load plugin
#define ZLOG_E_PLUGIN_SYMBOL         -9             //!< Invalid plugin
#define ZLOG_E_INVALID_LEVEL        -10             //!< Invalid logging level
#define ZLOG_E_APPENDER_NOTFOUND    -11             //!< Could not find appender with label
#define ZLOG_E_LAST_ERRNO           -11             //!< Always set to highest error number


/*
 * \brief plugin types
 */
typedef enum _eZLogPluginType {
    zlogPluginAppender  = 0,
    zlogPluginFormat    = 1,
} eZLogPluginType;


/*
 * \brief log levels
 */
typedef enum _eZLogLevel {
    zlogLevelNone       =          0,
    zlogLevelInfo       =          1,
    zlogLevelVerbose    =          2,
    zlogLevelWarning    =          4,
    zlogLevelError      =          8,
    zlogLevelCritical   =         16,
    zlogLevelFatal      =         32,
    zlogLevelUser       =         64,
    zlogLevelDebug      =        128,
    zlogLevelTrace      =        256,
    zlogLevelCustom0    =        512,
    zlogLevelCustom1    =       1024,
    zlogLevelCustom2    =       2048,
    zlogLevelCustom3    =       4096,
    zlogLevelCustom4    =       8192,
    zlogLevelCustom5    =      16384,
    zlogLevelCustom6    =      32768,
    zlogLevelCustom7    =      65536,
    zlogLevelCustom8    =     131072,
    zlogLevelCustom9    =     262144,
    zlogLevelCustom10   =     524288,
    zlogLevelCustom11   =    1048576,
    zlogLevelCustom12   =    2097152,
    zlogLevelCustom13   =    4194304,
    zlogLevelCustom14   =    8388608,
    zlogLevelCustom15   =   16777216,
    zlogLevelCustom16   =   33554432,
    zlogLevelCustom17   =   67108864,
    zlogLevelCustom18   =  134217728,
    zlogLevelCustom19   =  268435456,
    zlogLevelCustom20   =  536870912,
    zlogLevelCustom21   = 1073741824,
//    zlogLevelCustom22   = 2147483648
} eZLogLevel;


/*
 * appender options
 */
#define ZLOG_APP_OPT_NONE               0           //!< no options selected
#define ZLOG_APP_OPT_DUPLICATE          1           //!< Remove duplicate log entries


/*
 * data types
 */
typedef void *  zlogFormat;
typedef void *  zlogAppender;
typedef void *  zlogLogger;


/*
 * global variables
 */
extern int          zlogErrno;


/*
 * function declarations
 */
extern char *       zlogErrorString( int errno );

extern zlogFormat   zlogFormatDefine( char *name, char *format );
extern zlogFormat   zlogFormatDefault( void );
extern zlogFormat   zlogFormatFind( char *name );
extern char *       zlogFormatGetFormat( zlogFormat format_id );

extern unsigned int zlogLevelGetTop( void );
extern int          zlogLevelSetName( unsigned int level, char *name );

extern zlogAppender zlogAppenderDefine( char *name, char *type, char *parameters, zlogFormat format_id );
extern zlogAppender zlogAppenderSimple( char *name, char *params );
extern zlogAppender zlogAppenderFind( char *name );
extern zlogAppender zlogAppenderGetDefault( void );
extern int          zlogAppenderSetDefault( zlogAppender appender_id );
extern int          zlogAppenderSetFormat( zlogAppender appender_id, zlogFormat format_id );
extern int          zlogAppenderSetParameters( zlogAppender appender_id, void *parameters );
extern zlogFormat   zlogAppenderGetFormat( zlogAppender appender_id );
extern char *       zlogAppenderGetParameters( zlogAppender appender_id );
extern int          zlogAppenderGetOptions( zlogAppender appender_id );
extern int          zlogAppenderSetOptions( zlogAppender appender_id, int options );

extern char *       zlogPluginLoad( char *path );
extern char *       zlogPluginDir( void );

extern zlogLogger   zlogLoggerCreate( char *name, unsigned int levels );
extern zlogLogger   zlogLoggerFind( char *name );
extern int          zlogLoggerAddAppender( zlogLogger logger_id, zlogAppender appender_id, unsigned int levels, int ringdump );
extern int          zlogLoggerSetLevel( zlogLogger logger_id, unsigned int levels );
extern unsigned int zlogLoggerGetLevel( zlogLogger logger_id );
extern zlogAppender zlogLoggerGetAppenderList( zlogLogger logger_id, unsigned int position );
extern char *       zlogLoggerGetName( zlogLogger logger_id );

extern void         zlog( zlogLogger logger_id, unsigned int level, int msgid, char *message, ... );
extern void         zlogv( zlogLogger logger_id, unsigned int level, int msgid, char *message, va_list ap );
extern void         zlog_dynmem( zlogLogger logger_id, unsigned int level, int msgid, char *message, ... );
extern void         zlog_dynmemv( zlogLogger logger_id, unsigned int level, int msgid, char *message, va_list ap );
extern int          zlogRingDump( zlogLogger logger_id );
extern int          zlogDumpStructures( zlogLogger logger_id );

#endif /*ZLOGGER_H_*/
