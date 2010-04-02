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
 * \if DeveloperDocs
 *   \brief User authentication support
 * \endif
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef WITH_AUTHENTICATION
#include "polarssl/aes.h"
#include "polarssl/dhm.h"

#include "polarssl/havege.h"
#endif

#include "enmx_lib.private.h"


/*!
 * \addtogroup xgBus
 * @{
 */

/*!
 * \brief authenticate user
 * 
 * eibnetmux supports simple, password-based authentication for its socketserver clients.
 * To authenticate, a client must send username and corresponding password (full, not hashed).
 * To protect against network sniffers, secrets are encrypted before transmission.
 *
 * To calculate the encryption key, the client initiates the Diffie-Hellman-Merkle key exchange.
 * It receives the corresponding DHM parameters from the server, calculates its own public key
 * and sends it to the server. With this, both parties have enough information to independently
 * and secretly compute a shared session key which is used here only for encryption.
 * 
 * The C library only supports authentication if compiled with authentication support
 * which depends on the availability of the PolarSSL library.
 * 
 * \param   handle          connection handle as returned by enmx_open()
 * \param   user            name of user trying to authenticate
 * \param   password        user's password
 * 
 * \return                  0: ok, -1: error (get error code with enmx_geterror), ENMX_E_NO_CONNECTION: invalid handle
 */
int enmx_auth( ENMX_HANDLE handle, char *user, char *password )
{
    sConnectionInfo         *connInfo;
#ifdef WITH_AUTHENTICATION
    SOCKET_CMD_HEAD         cmd_head;
    SOCKET_RSP_HEAD         rsp_head;
    int                     ecode;
    int                     len;
    havege_state            hs;
    dhm_context             dhm;
    aes_context             aes;
    unsigned char           buf[1024];
    unsigned char           *ptr_start;
    unsigned char           *ptr_end;
    unsigned char           iv[16];
    int                     iv_off;
#endif
    
    // get connection info block
    for( connInfo = enmx_connections; connInfo != NULL; connInfo = connInfo->next ) {
        if( connInfo->socket == handle ) {
            break;
        }
    }
    if( connInfo == NULL ) {
        return( ENMX_E_NO_CONNECTION );
    }
    
#ifdef WITH_AUTHENTICATION
    // check parameters
    if( strlen( user ) > SOCKET_NAME_MAX_LENGTH || strlen( password ) > SOCKET_PASSWORD_MAX_LENGTH ) {
        connInfo->errorcode = ENMX_E_PARAMETER;
        return( -1 );
    }
    
    // request key exchange using diffie-hellman-merkle
    cmd_head.cmd = SOCKET_CMD_KEY;
    cmd_head.address = 0;
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    
    // get server's DHM parameters
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    if( rsp_head.status == SOCKET_STAT_ERROR ) {
        connInfo->errorcode = ENMX_E_AUTH_UNSUPPORTED;
        return( -1 );
    }
    rsp_head.size = ntohs( rsp_head.size );
    ecode = connInfo->recv( handle, buf, rsp_head.size, 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    memset( &dhm, 0, sizeof( dhm ));
    havege_init( &hs );
    ptr_start = buf;
    ptr_end = buf + rsp_head.size;
    dhm_read_params( &dhm, &ptr_start, ptr_end );
    if( dhm.len < 64 || dhm.len > 256 ) {
        connInfo->errorcode = ENMX_E_DHM_FAILURE;
        dhm_free( &dhm );
        return( -1 );
    }
    
    // create and send our public key
    len = dhm.len;
    dhm_make_public( &dhm, 256, buf, len, havege_rand, &hs );
    cmd_head.cmd = SOCKET_CMD_DHM;
    cmd_head.address = htons( len );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        dhm_free( &dhm );
        return( -1 );
    }
    ecode = connInfo->send( handle, buf, len );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        dhm_free( &dhm );
        return( -1 );
    }
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        dhm_free( &dhm );
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_DHM ) {
        connInfo->errorcode = ENMX_E_DHM_FAILURE;
        dhm_free( &dhm );
        return( -1 );
    }
    
    // calculate the secret key
    dhm_calc_secret( &dhm, buf, &len );
    dhm_free( &dhm );
    
    // encrypt username & password
    // format: ecb( iv ), cfb( user \0 password \0 )
    aes_setkey_enc( &aes, buf, 256 );
    memset( iv, '\0', 16 );
    for( len = 0; len < 16; len += 4 ) {
        ecode = havege_rand( &hs );
        memcpy( &iv[len], &ecode, sizeof( int ));
    }
    aes_crypt_ecb( &aes, AES_ENCRYPT, iv, buf );
    len = 16;
    strcpy( (char *)(buf + len), user );
    len += strlen( user ) +1;
    strcpy( (char *)(buf + len), password );
    len += strlen( password ) + 1;
    iv_off = 0;
    aes_crypt_cfb128( &aes, AES_ENCRYPT, len -16, &iv_off, iv, buf + 16, buf + 16 );
    
    // authenticate to eibnetmux
    cmd_head.cmd = SOCKET_CMD_AUTH;
    cmd_head.address = htons( len );
    ecode = connInfo->send( handle, (unsigned char *)&cmd_head, sizeof( cmd_head ));
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    ecode = connInfo->send( handle, buf, len );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        return( -1 );
    }
    ecode = connInfo->recv( handle, (unsigned char *)&rsp_head, sizeof( rsp_head ), 1 );
    if( ecode < 0 ) {
        connInfo->errorcode = ecode;
        dhm_free( &dhm );
        return( -1 );
    }
    if( rsp_head.status != SOCKET_STAT_AUTH ) {
        connInfo->errorcode = ENMX_E_AUTH_FAILURE;
        return( -1 );
    }
    
    connInfo->errorcode = ENMX_E_NO_ERROR;
    return( 0 );
#else
    connInfo->errorcode = ENMX_E_AUTH_UNSUPPORTED;
    return( -1 );
#endif
}
/*! @} */
