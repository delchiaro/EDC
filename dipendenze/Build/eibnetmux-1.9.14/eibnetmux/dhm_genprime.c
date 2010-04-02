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

/*
 * copied almost verbatim from the PolarSSL library
 * changed only slightly
 */

/*
 *  Diffie-Hellman-Merkle key exchange (prime generation)
 *
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdio.h>

#include "polarssl/bignum.h"
#include "polarssl/config.h"
#include "polarssl/havege.h"

/*
 * Note: G = 4 is always a quadratic residue mod P,
 * so it is a generator of order Q (with P = 2*Q+1).
 */
#define DH_P_SIZE 1024
#define GENERATOR "4"

int main( void )
{
    int ret = 1;

#if defined(POLARSSL_GENPRIME)
    mpi G, P, Q;
    havege_state hs;

    mpi_init( &G, &P, &Q, NULL );
    mpi_read_string( &G, 10, GENERATOR );

    printf( "Seeding the random number generator..." );
    fflush( stdout );

    havege_init( &hs );

    printf( " ok\nGenerating the modulus, please wait..." );
    fflush( stdout );

    /*
     * This can take a long time...
     */
    if( ( ret = mpi_gen_prime( &P, DH_P_SIZE, 1,
                               havege_rand, &hs ) ) != 0 )
    {
        printf( " failed\n  ! mpi_gen_prime returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\nVerifying that Q = (P-1)/2 is prime..." );
    fflush( stdout );

    if( ( ret = mpi_sub_int( &Q, &P, 1 ) ) != 0 )
    {
        printf( " failed\n  ! mpi_sub_int returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mpi_div_int( &Q, NULL, &Q, 2 ) ) != 0 )
    {
        printf( " failed\n  ! mpi_div_int returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mpi_is_prime( &Q, havege_rand, &hs ) ) != 0 )
    {
        printf( " failed\n  ! mpi_is_prime returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n\nThe following two lines can be copied directly to the eibnetmux_security file.\n" );
    fflush( stdout );

    if( ( ret = mpi_write_file( "P = ", &P, 16, stdout ) != 0 ) ||
        ( ret = mpi_write_file( "G = ", &G, 16, stdout ) != 0 ) )
    {
        printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

exit:

    mpi_free( &Q, &P, &G, NULL );
#else
    printf( "\n  ! Prime-number generation is not available.\n\n" );
#endif

    return( ret );
}
