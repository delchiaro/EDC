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
 *   \brief Standard file appender - writes log messages to a local file
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

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
static int fileOpen( sAppender *pApp );
static int fileClose( sAppender *pApp );
static int fileLog( sAppender *pApp, unsigned int level, char *message );
static int fileCheck( char *params );


/*
 * Local variables
 */
static sAppenderPlugin     structFile = {
        "file:", "%s", /* 1, */ fileOpen, fileClose, fileLog, fileCheck, NULL
};


/*!
 * \brief init file appender
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
sAppenderPlugin *zlogFile_Init( void )
{
    return( &structFile );
}


/*!
 * \brief check parameters for file appender
 * 
 * \param   params          parameter string
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int fileCheck( char *params )
{
    if( params == NULL || *params == '\0' ) {
        return( ZLOG_E_PARAMETERS );
    }
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief open file appender
 * 
 * \param   pApp            pointer to appender
 * \param   params          pointer to parameters
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int fileOpen( sAppender *pApp )
{
    FILE    *fp;
    
    fp = (FILE *)pApp->channel;
    if( fp != NULL ) {
        fclose( fp );
    }
    fp = fopen( pApp->parameters, "a" );
    pApp->channel = (void *)fp;
    
    if( fp == NULL ) {
        return( ZLOG_E_CHANNEL );
    }
    return( ZLOG_NO_ERROR );
}


static int fileClose( sAppender *pApp )
{
    FILE    *fp;
    
    fp = (FILE *)pApp->channel;
    if( fp != NULL ) {
        fclose( fp );
    }
    pApp->channel = NULL;
    return( ZLOG_NO_ERROR );
}


static int fileLog( sAppender *pApp, unsigned int level, char *message )
{
    if( pApp->channel != NULL ) {
        // fprintf( pApp->channel, message );
        fputs( message, pApp->channel );
        fputc( '\n', pApp->channel );
        fflush( pApp->channel );
        return( ZLOG_NO_ERROR );
    }
    
    return( ZLOG_E_CHANNEL );
}
/*!
 * \endcond
 */
/*! @} */
