/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2009 Urs Zurbuchen <going_nuts@users.sourceforge.net>
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
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <polarssl/sha2.h>

#define HASH_SIZE   32

int main( int argc, char **argv )
{
    unsigned char   password[255];
    unsigned char   password_hash[HASH_SIZE];
    char            *result;
    int             idx;
    struct termios  term_settings;
    
    // get password
    if( isatty( 0 )) {
        printf( "Password: " );
        tcgetattr( 0, &term_settings );
        term_settings.c_lflag &= (~ECHO);
        tcsetattr( 0, TCSANOW, &term_settings );
        term_settings.c_lflag |= ECHO;
    }
    result = fgets( (char *)password, 256, stdin );
    if( isatty( 0 )) {
        printf( "\n" );
        tcsetattr( 0, TCSANOW, &term_settings );
    }
    if( result == NULL ) {
        fprintf( stderr, "Error reading password - cannot continue\n" );
        return( -1 );
    }
    if( password[strlen((char *)password) -1] == '\n' ) {
        password[strlen((char *)password) -1] = '\0';
    }
    
    // compute hash
    memset( password_hash, '\0', HASH_SIZE );
    sha2( password, strlen( (char *)password ), password_hash, 0 );
    
    // print hash
    for( idx = 0; idx < HASH_SIZE; idx++ ) {
        printf( "%02x", password_hash[idx] );
    }
    printf( "\n" );
    
    return( 0 );
}
