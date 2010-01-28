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
 *   \brief Syslog appender - send log messages to local syslog process
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include "zlogger.private.h"


/*!
 * \addtogroup xgAppender
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

/*
 * Local function declarations
 */
static int syslogOpen( sAppender *pApp );
static int syslogClose( sAppender *pApp );
static int syslogLog( sAppender *pApp, unsigned int level_idx, char *message );
static int syslogCheck( char *params );


/*
 * Local variables
 */
static sAppenderPlugin     structSyslog = {
        "syslog:", "%s", /* 0, */ syslogOpen, syslogClose, syslogLog, syslogCheck, NULL
};
static int syslogPriority[9] = {
        // -1, // zlogLevelNone
        6,  // zlogLevelInfo
        6,  // zlogLevelVerbose
        4,  // zlogLevelWarning
        3,  // zlogLevelError
        2,  // zlogLevelCritical
        0,  // zlogLevelFatal
        5,  // zlogLevelUser
        7,  // zlogLevelDebug
        7   // zlogLevelTrace
};


/*!
 * \brief init syslog appender
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
sAppenderPlugin *zlogSyslog_Init( void )
{
    return( &structSyslog );
}


/*!
 * \brief check parameters for syslog appender
 * 
 * \param   params          parameter string
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int syslogCheck( char *params )
{
    if( params == NULL || *params == '\0' ) {
        return( ZLOG_E_PARAMETERS );
    }
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief open syslog appender
 * 
 * \param   pApp            pointer to appender
 *          params          pointer to parameters
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int syslogOpen( sAppender *pApp )
{
    if( strcasecmp( pApp->parameters, "user" ) == 0 ) {
        pApp->channel = (void *)LOG_USER;
    } else if( strcasecmp( pApp->parameters, "mail" ) == 0 ) {
            pApp->channel = (void *)LOG_MAIL;
    } else if( strcasecmp( pApp->parameters, "daemon" ) == 0 ) {
            pApp->channel = (void *)LOG_DAEMON;
    } else if( strcasecmp( pApp->parameters, "auth" ) == 0 ) {
            pApp->channel = (void *)LOG_AUTH;
    } else if( strcasecmp( pApp->parameters, "lpr" ) == 0 ) {
            pApp->channel = (void *)LOG_LPR;
    } else if( strcasecmp( pApp->parameters, "news" ) == 0 ) {
            pApp->channel = (void *)LOG_NEWS;
    } else if( strcasecmp( pApp->parameters, "uucp" ) == 0 ) {
            pApp->channel = (void *)LOG_UUCP;
    } else if( strcasecmp( pApp->parameters, "cron" ) == 0 ) {
            pApp->channel = (void *)LOG_CRON;
    } else if( strcasecmp( pApp->parameters, "authpriv" ) == 0 ) {
            pApp->channel = (void *)LOG_AUTHPRIV;
    } else if( strcasecmp( pApp->parameters, "ftp" ) == 0 ) {
            pApp->channel = (void *)LOG_FTP;
    } else if( strncasecmp( pApp->parameters, "local", 5 ) == 0 ) {
        pApp->channel = (void *)(LOG_LOCAL0 + (atoi( &pApp->parameters[5] ) << 3));
    }
    if( pApp->channel == NULL ) {
        return( ZLOG_E_SYSLOG );
    }
    
    openlog( pApp->name, LOG_ODELAY, (int)pApp->channel );
    return( ZLOG_NO_ERROR );
}


static int syslogClose( sAppender *pApp )
{
    closelog();
    pApp->channel = NULL;
    
    return( ZLOG_NO_ERROR );
}


static int syslogLog( sAppender *pApp, unsigned int level_idx, char *message )
{
    int     prio;
    
    prio = (level_idx <= 8) ? syslogPriority[level_idx] : 6;
    syslog( prio, "%s", message );
    return( ZLOG_NO_ERROR );
}

/*!
 * \endcond
 */
/*! @} */
