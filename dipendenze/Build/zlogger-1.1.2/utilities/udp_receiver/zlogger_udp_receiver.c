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
 *   \brief UDP appender - send log messages over a UDP connection to a log server
 * \endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <time.h>


void usage( char *prog )
{
    fprintf( stderr, "Usage is: %s <port number>\n", prog );
}

#define BUFSIZE 512

int main( int argc, char **argv )
{
    int                     port = 0;
    int                     sock;
    ssize_t                 len;
    socklen_t               addrlen;
    time_t                  now;
    struct tm               *ltime;
    char                    buf[BUFSIZE];
    struct sockaddr_in      src, target;
    
    if( argc == 2 ) {
        port = atoi( argv[1] );
    }
    
    if( port == 0 ) {
        usage( basename( argv[0] ));
        exit( -1 );
    }
    
    printf( "TraceHost: listening on %d (%x/%d)\n", port, htons( port ), htons( port ));
    port = htons( port );
    
    sock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if( sock == -1 ) {
        fprintf( stderr, "error creating socket\n" );
        exit( -2 );
    }

    bzero( (void *)&target, sizeof( target ));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl( INADDR_ANY );
    target.sin_port = port;

    if( bind( sock, (struct sockaddr*)&target, sizeof( target )) == -1 ) {
        fprintf( stderr, "error binding address\n" );
        exit( -3 );
    }
    
    addrlen = sizeof( src );
    
    while( 1 ) {
        bzero( (void *)&src, sizeof( src ));
        len = recvfrom( sock, (void*)buf, BUFSIZE, 0, (struct sockaddr*)&src, &addrlen );
        if( len < 0 ) {
            perror( NULL );
        } else {
            now = time( NULL );
            ltime = localtime( &now );
            printf( "%04d/%02d/%02d %02d:%02d:%02d [%s] - %.*s", 
                    ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday,
                    ltime->tm_hour, ltime->tm_min, ltime->tm_sec,
                    inet_ntoa( src.sin_addr ),
                    len, buf );
        }
    }
}
