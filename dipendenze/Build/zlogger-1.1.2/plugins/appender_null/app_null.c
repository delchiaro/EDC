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
 *   \brief Plugin null appender - discards log messages
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
static int nullOpen( sAppender *pApp );
static int nullClose( sAppender *pApp );
static int nullLog( sAppender *pApp, unsigned int level, char *message );
static int nullCheck( char *params );


/*
 * Local variables
 */
static sAppenderPlugin     structFile = {
        "null:", "%s", /* 0, */ nullOpen, nullClose, nullLog, nullCheck, NULL
};


/*!
 * \brief return plugin type
 * 
 * \return                  zlogPluginAppender
 */
eZLogPluginType zlogPlugin_GetType( void )
{
    return( zlogPluginAppender );
}


/*!
 * \brief init null appender
 * 
 * \return                  pointer to plugin interface definition, NULL upon error
 */
sAppenderPlugin *zlogPlugin_Init( void )
{
    return( &structFile );
}


/*!
 * \brief check parameters for null appender
 * 
 * \param   params          parameter string
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int nullCheck( char *params )
{
    if( params != NULL && *params != '\0' ) {
        return( ZLOG_E_PARAMETERS );
    }
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief open null appender
 * 
 * \param   pApp            pointer to appender
 * \param   params          pointer to parameters
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int nullOpen( sAppender *pApp )
{
    pApp->channel = (void *) 1;
    return( ZLOG_NO_ERROR );
}


static int nullClose( sAppender *pApp )
{
    pApp->channel = NULL;
    return( ZLOG_NO_ERROR );
}


static int nullLog( sAppender *pApp, unsigned int level, char *message )
{
    return( (pApp->channel == NULL) ? ZLOG_E_CHANNEL : ZLOG_NO_ERROR );
}
/*!
 * \endcond
 */
/*! @} */
