/*
 * common functions for samples
 * 
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2008 Urs Zurbuchen <software@marmira.com>
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
 *   \brief Common functions for samples
 * \endif
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <arpa/inet.h>

#include <eibnetmux/enmx_lib.h>


/*
 * get password
 */
int getpassword( char *pwd )
{
    struct termios  term_settings;
    char            *result;
    
    if( isatty( 0 )) {
        printf( "Password: " );
    }
    
    tcgetattr( 0, &term_settings );
    term_settings.c_lflag &= (~ECHO);
    tcsetattr( 0, TCSANOW, &term_settings );
    term_settings.c_lflag |= ECHO;
    
    result = fgets( pwd, 256, stdin );
    printf( "\n" );
    
    tcsetattr( 0, TCSANOW, &term_settings );
    
    if( result == NULL ) {
        return( -1 );
    }
    if( pwd[strlen(pwd) -1] == '\n' ) {
        pwd[strlen(pwd) -1] = '\0';
    }
    
    return( 0 );
}


/*
 * print delta time
 */
char *deltatime( uint32_t seconds )
{
    static char     buf[64];
    int             days = 0;
    int             hours = 0;
    int             minutes = 0;
    
    days = seconds / 86400;
    seconds %= 86400;
    hours = seconds / 3600;
    seconds %= 3600;
    minutes = seconds / 60;
    seconds %= 60;
    
    if( days > 0 ) {
        sprintf( buf, "%d days, %02d:%02d:%02d", days, hours, minutes, seconds );
    } else if( hours > 0 ) {
        sprintf( buf, "%02d:%02d:%02d", hours, minutes, seconds );
    } else if( minutes > 0 ) {
        sprintf( buf, "%d minutes, %d seconds", minutes, seconds );
    } else {
        sprintf( buf, "%d seconds", seconds );
    }
    
    return( buf );
}


/*
 * print ip address
 */
char *ip_addr( uint32_t ip )
{
    static char     text[17];
    
    ip = htonl( ip );
    sprintf( text, "%d.%d.%d.%d", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff );
    return( text );
}


/*
 * produce hexdump of a (binary) string
 */
char *hexdump( void *string, int len, int spaces )
{
    int             idx = 0;
    unsigned char   *ptr;
    static char     *buf = NULL;
    static int      buflen = 0;

    if( string == NULL ) {
        if( buf != NULL ) {
            free( buf );
            buflen = 0;
        }
    }
    
    if( len == 0 )
        len = strlen( string );
    if( (len *2 + (spaces ? len : 0) +1) > buflen ) {
        buflen = len *2 + (spaces ? len : 0) +1;
        if( buf == NULL ) {
            buf = malloc( buflen );
        } else {
            buf = realloc( buf, buflen );
        }
        if( buf == NULL ) {
            fprintf( stderr, "Out of memory: %s\n", strerror( errno ));
            exit( -9 );
        }
    }
    
    ptr = string;
    while( len > 0 ) {
        sprintf( &buf[idx], "%2.2x", *ptr );
        idx +=2;
        if( spaces ) {
            sprintf( &buf[idx], " " );
            idx++;
        }
        ptr++;
        len--;
    }

    return( buf );
}


/*
 * Shutdown
 * 
 * catches SIGINT and SIGTERM and shuts down
 */
extern unsigned char    conn_state;
extern ENMX_HANDLE      sock_con;

void Shutdown( int arg )
{
    fprintf( stderr, "Signal received - shutting down\n" );

    // close monitoring connection
    if( conn_state != 0 ) {
        fprintf( stderr, "Disconnecting from eibnetmux\n" );
        enmx_close( sock_con );
    }

    exit( 0 );
}
