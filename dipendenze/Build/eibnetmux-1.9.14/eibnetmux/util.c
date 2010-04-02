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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <pth.h>

#include "eibnetmux.h"
#include "include/log.h"

void Shutdown( void )
{
    pth_raise( tid_main, SIGINT );
    while( true ) {
        pth_yield( NULL );
    }
}


char *hexdump( void *module, void *string, int len )
{
    int             idx = 0;
    unsigned char   *ptr;
    char            *buf;

    if( len == 0 )
        len = strlen( string );
    buf = allocMemory( module, len *3 +1 );
    
    ptr = string;
    while( len > 0 ) {
        sprintf( &buf[idx], "%2.2x ", *ptr );
        ptr++;
        len--;
        idx += 3;
    }

    return( buf );
}

/*
 * can't use inet_ntoa() as it is not thread-safe
 */
char *ip_addr( uint32_t ip, char *buf )
{
    static char     text[17];
    unsigned char   *ptr;
    
    buf = (buf != NULL) ? buf : text;
    ptr = (unsigned char *)&ip;
    sprintf( buf, "%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3] );
    return( buf );
}

char *knx_group( void *module, uint16_t knxaddress )
{
    char   *buf;
    
    knxaddress = ntohs( knxaddress );
    buf = allocMemory( module, 10 );
    sprintf( buf, "%d/%d/%d", (knxaddress >> 11) & 0x0f, (knxaddress >> 8) & 0x07, knxaddress & 0xff );
    return( buf );
}

char *knx_physical( void *module, uint16_t knxaddress )
{
    char   *buf;
    
    knxaddress = ntohs( knxaddress );
    buf = allocMemory( module, 10 );
    sprintf( buf, "%d.%d.%d", (knxaddress >> 12) & 0x0f, (knxaddress >> 8) & 0x0f, knxaddress & 0xff );
    return( buf );
}

void *allocMemory( void *module, size_t size )
{
    void    *ptr;
    
    ptr = malloc( size );
    if( ptr == NULL ) {
        logFatal( module, msgMemory );
        Shutdown();
    }
    return( ptr );
}


/*!
 * \brief Append 1-4 bytes to end of buffer
 * 
 * \long Be careful with conversions for low- and big-endian systems
 * If we're called with a 16-bit value, for example 1279:
 *      16-bit: 1279
 *      low-endian: ff 04
 *      big-endian: 04 ff
 *      network:    04 ff
 * 
 *      32-bit conversion (because parameter is 32-bit):
 *      low-endian: 04 ff 00 00
 *      big-endian: 00 00 04 ff
 *
 * \param       index                   start position in buffer where bytes go
 * \param       buf                     pointer to start of buffer (where index = 0)
 * \param       size                    number of bytes to append
 * \param       value                   bytes to append, numeric value
 * 
 * \return                              start position in buffer where next byte goes
 */
uint16_t AppendBytes( uint16_t index, char *buf, uint16_t size, uint32_t value )
{
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned char   *ptr;
    
    ptr = (unsigned char *)&value;
    if( size == 1 ) ptr += 3;
    if( size == 2 ) ptr += 2;
    memcpy( &buf[index], ptr, size );
#else
    memcpy( &buf[index], &value, size );
#endif
    return( index + size );
}


/*!
 * \brief Round a double to the closest full integer value
 *
 * As I could get neither calls to round, rint, nor to nearbyint to compile correctly,
 * here's a quick rounding function.
 * It works correctly for positive and negative values.
 * It (ab)uses a trick where conversion of a double to an integer just drops the decimals.
 *
 * \param       real                    real number
 *
 * \return                              number rounded to closest integer
 */
int round_double( double real )
{
    return( (real < 0) ? real -0.5 : real + 0.5 );
}


/*!
 * \brief Get minimum
 * 
 * \param       v1                      first value
 * \param       v2                      second value
 * 
 * \return                              lower value of p1 and p2
 */
uint16_t min16( uint16_t v1, uint16_t v2 )
{
    return( (v1 <= v2) ? v1 : v2 );
}


/*
void     *mempcpy( void *dest, void *source, uint16_t len )
{
        memcpy( dest, source, len );
        return( dest + len );
}
*/


/*!
 * \brief convert from hex ascii to integer
 *
 * \param       c                       hex ascii character
 * \param       r                       pointer to buffer receiving converted result
 *
 * \return                              0: ok, -1: invalid character
 */
int fromHex( unsigned char c, unsigned char *r )
{
    c = tolower( c );
    if( !isxdigit( c )) {
        return( -1 );
    }
    *r = (isalpha( c )) ? (c - 'a' + 10) : (c - '0');
    return( 0 );
}


/*!
 * \brief Return next available connection id
 * 
 * Connection ids are used to identify a client connection for selected management functions
 * (such as forcibly closing the session). The ids, therefore, have no security implications
 * and are assigned consecutively.
 * If all possible ids have been used, roll-over and re-start from 1, making sure not to
 * assign the same id twice.
 * The algorithm tries to be as fast as possible and to minimize the checks for conflicts, etc.
 * 
 * Note: 0 is not used as connection id (reserved to indicate no active connection)
 * 
 * \param       module                  identifies logger for calling module
 * \param       getids                  pointer to function returning list of all currently allocated ids
 * 
 * \return                              connection id
 */
uint32_t getConnectionId( void *module, int (*getids)( void *system, uint32_t **array, int entries, uint32_t threshold ))
{
#define MAXID       0xffffffff
    static uint32_t lastconnection_id = 0;      // last assigned connection id, incremented with every new connection
    static uint32_t last_free_id = MAXID;       // all ids up to this one are available
    int             loop;
    int             idx;
    int             entries;
    uint32_t        tmp;
    uint32_t        *sorted;
    
    /*
    // if next id has not been used yet, immediately return it
    if( rollover == FALSE ) {
        if( ++lastconnection_id != 0 ) {
            return( lastconnection_id );
        }
        rollover = TRUE;
        last_free_id = 0;
    }
    */
    
    // return ids up to last free one
    if( lastconnection_id < last_free_id ) {
        return( ++lastconnection_id );
    }
    
    // determine next first & last free ids
    // connection 0 is reserved for eibnetmux'c client connection to upstream server
    // first, create a sorted list of used ids greater than the last free one
    entries = 0;
    last_free_id++;
    entries = socketGetUsedIds( module, &sorted, 0, last_free_id );
    entries = eibGetUsedIds( module, &sorted, entries, last_free_id );
    if( entries == 0 ) {
        free( sorted );
        lastconnection_id = (last_free_id == 0) ? 1 : last_free_id;
        last_free_id = MAXID;
        return( lastconnection_id );
    }
    for( idx = 1; idx < entries; idx++ ) {
        for( loop = 0; loop < idx; loop++ ) {
            if( sorted[idx] >= sorted[loop] ) {
                continue;
            }
            tmp = sorted[idx];
            memmove( &sorted[loop +1], &sorted[loop], (idx - loop) * sizeof( uint32_t ));
            sorted[loop] = tmp;
            break;
        }
    }
    
    // determine first available id
    // skip over consecutive used ones
    for( loop = 0; loop < entries -1; loop++ ) {
        if( sorted[loop] +1 != sorted[loop +1] ) {
            break;
        }
    }
    lastconnection_id = sorted[loop] +1;
    if( loop < entries -1 ) {
        last_free_id = sorted[loop +1];
    } else {
        last_free_id = MAXID;
    }
    free( sorted );
    
    return( lastconnection_id );
}


/*
 * readFromSocket
 * 
 * read data from socket
 * check for timeout or aborted socket connection
 */
int readFromSocket( void *module, int sock, int connid, void *ptr, uint16_t bytes, uint16_t maxbytes, unsigned int timeout )
{
    pth_event_t     ev_wakeup = NULL;
    time_t          secs;
    int             len;
    int             bytes_read;
    int             to_read;
    char            tmp;
    boolean         abort;
    unsigned char   *buf;

    if( connid >= config.eibdclients ) {
        return( -1 );
    }
    
    logDebug( module, "Connection %d: reading %d bytes (maximum %d)", connid, bytes, maxbytes );
    
    abort = false;
    buf = ptr;
    to_read = min16( bytes, maxbytes );
    if( timeout > 0 ) {
        secs = time( NULL ) + timeout;
        ev_wakeup = pth_event( PTH_EVENT_TIME, pth_time( secs, 0 ));
    }
    for( bytes_read = 0; bytes_read < to_read; ) {
        if( ev_wakeup != NULL ) {
            len = pth_read_ev( sock, &buf[bytes_read], to_read - bytes_read, ev_wakeup );
            if( pth_event_status( ev_wakeup ) == PTH_STATUS_OCCURRED ) {
                // timeout on read
                logError( module, msgSocketNoData, connid, timeout );
                abort = true;
                break;
            }
        } else {
            len = pth_read( sock, &buf[bytes_read], to_read - bytes_read );
        }
        bytes_read += len;
        if( len == 0 ) {
            // end of file means client closed connection
            if( bytes_read == 0 ) {
                // - after the previous command - close
                logVerbose( module, msgSocketConnectionClosed, connid );
            } else {
                // - in the middle of sending something - abort
                logVerbose( module, msgSocketUnexpectedClose, connid );
            }
            abort = true;
            break;
        }
    }
    
    if( bytes_read > 0 ) {
        buf = (unsigned char *)hexdump( module, ptr, bytes_read );
        if( module == logModuleSocketServer ) {
            logTraceSocket( module, msgSocketReadData, connid, bytes_read, buf );
        } else {
            logTraceEIBD( module, msgSocketReadData, connid, bytes_read, buf );
        }
        free( buf );
    }
    
    // skip over rest if maxbytes was exhausted
    if( abort == false ) {
        while( bytes_read < bytes ) {
            if( ev_wakeup != NULL ) {
                len = pth_read_ev( sock, &tmp, 1, ev_wakeup );
                if( pth_event_status( ev_wakeup ) == PTH_STATUS_OCCURRED ) {
                    // timeout on read
                    logError( module, msgSocketNoData, connid, timeout );
                    abort = true;
                    break;
                }
            } else {
                len = pth_read( sock, &tmp, 1 );
            }
            bytes_read += len;
            if( len == 0 ) {
                // end of file means client closed connection - abort
                logVerbose( module, msgSocketUnexpectedClose, connid );
                abort = true;
                break;
            }
        }
    }
    
    if( ev_wakeup != NULL ) {
        pth_event_free( ev_wakeup, PTH_FREE_ALL );
    }
    if( abort == true ) {
        return( -1 );
    }
    
    return( 0 );
}
