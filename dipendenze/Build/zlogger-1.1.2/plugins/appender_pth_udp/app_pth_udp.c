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
 *   \brief Plugin UDP appender - send log messages over a UDP connection to a log server using PTH functions
 * \endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pth.h>


#include "zlogger.private.h"


/*!
 * \addtogroup xgAppender
 * @{
 */

/*!
 * \cond DeveloperDocs
 */

typedef struct _sUDPSocket {
    char    *hostname;
    ulong   ip;
    int     port;
    int     sock;
} sUDPSocket;


/*
 * Local function declarations
 */
static int udpOpen( sAppender *pApp );
static int udpClose( sAppender *pApp );
static int udpLog( sAppender *pApp, unsigned int level, char *message );
static int udpCheck( char *params );


/*
 * Local variables
 */
static sAppenderPlugin     structUDP = {
        "udp:", "%s", /* 1, */ udpOpen, udpClose, udpLog, udpCheck, NULL
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
 * \return                  pointer to new format definition, NULL upon error
 */
sAppenderPlugin *zlogPlugin_Init( void )
{
    return( &structUDP );
}


/*!
 * \brief check parameters for udp appender
 * 
 * \param   params          parameter string
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int udpCheck( char *params )
{
    if( params == NULL || *params == '\0' || atoi( params ) <= 0 ) {
        return( ZLOG_E_PARAMETERS );
    }
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief open udp appender
 * 
 * \param   pApp            pointer to appender
 * \param   params          pointer to parameters
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int udpOpen( sAppender *pApp )
{
    char        *ptr;
    sUDPSocket  *channel;
    int         len;
    int         port;
    uint32_t    *addr;
    struct hostent  *h;
    
    ptr = strchr( pApp->parameters, ':' );
    if( ptr != NULL ) {
        len = ptr - pApp->parameters;
        port = htons( atoi( ptr ));
    } else {
        len = strlen( pApp->parameters );
        port = htons( 9999 );
    }
    if( (channel = malloc( sizeof( sUDPSocket ))) == NULL ) {
        return( ZLOG_E_OUTOFMEMORY );
    }
    channel->hostname = malloc( len + 1 );
    if( channel == NULL ) {
        free( channel );
        return( ZLOG_E_OUTOFMEMORY );
    }
    memset( channel->hostname, '\0', len +1 );
    strncpy( channel->hostname, pApp->parameters, len );
    h = gethostbyname( channel->hostname );
    if( !h ) {
        free( channel->hostname );
        free( channel );
        return( ZLOG_E_CHANNEL );
    }
    
    addr = (uint32_t *)(h->h_addr_list[0]);
    channel->ip = *addr;
    channel->port = port;
    channel->sock = 0;
    pApp->channel = (void *)channel;
    
    return( ZLOG_NO_ERROR );
}


static int udpClose( sAppender *pApp )
{
    sUDPSocket  *channel;
    
    channel = (sUDPSocket *)pApp->channel;
    if( channel != NULL && channel->sock != 0 ) {
        close( channel->sock );
        channel->sock = 0;
    }
    return( ZLOG_NO_ERROR );
}


static int udpLog( sAppender *pApp, unsigned int level, char *message )
{
    sUDPSocket              *channel;
    struct sockaddr_in      src, dest;
    int                     dest_len;
    
    channel = (sUDPSocket *)pApp->channel;
    if( channel->sock == 0 ) {
        bzero( (void *)&src, sizeof( src ));
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl( INADDR_ANY );
        src.sin_port = htons( 0 );
        
        channel->sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
        if( channel->sock < 0 || bind( channel->sock, (struct sockaddr *)&src, sizeof( src )) == -1 ) {
            channel->sock = 0;
            return( ZLOG_E_CHANNEL );
        }
    }
    if( channel->sock != 0 ) {
        bzero( (void *)&dest, sizeof( dest ));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = channel->ip;
        dest.sin_port = channel->port;
        dest_len = sizeof( dest );
        pth_sendto( channel->sock, message, strlen( message ), 0, (struct sockaddr *)&dest, dest_len );
    }
    
    return( ZLOG_NO_ERROR );
}
/*!
 * \endcond
 */
/*! @} */
