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
 *   \brief Ring buffer appender - log messages are kept in memory
 * \endif
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "zlogger.private.h"


/*!
 * \addtogroup xgAppender
 * @{
 */
#define MAGIC_RINGBUFFER_TAG_1      "zLogRingBuffer_1"
#define MAGIC_RINGBUFFER_TAG_2      "zLogRingBuffer_2"


/*!
 * \cond DeveloperDocs
 */

/*
 * Local structures
 */
typedef struct _sRing {
    char        _magic[MAGIC_MAX_LENGTH];
    char        *tail;              //!< Where to put next log entry. Always points to first byte after '\0'
    char        *head;              //!< Oldest full log line
    char        *end;               //!< Last byte of ringbuffer
    int         size;               //!< In bytes
    char        *buffer;            //!< Pointer to ring buffer
    char        _magic2[MAGIC_MAX_LENGTH];
} sRing;


/*
 * Local function declarations
 */
static int ringOpen( sAppender *pApp );
static int ringClose( sAppender *pApp );
static int ringLog( sAppender *pApp, unsigned int level, char *message );
static int ringCheck( char *params );


/*
 * Local variables
 */
static sAppenderPlugin     structRing = {
        "ring:", "%d", /* 1, */ ringOpen, ringClose, ringLog, ringCheck, NULL
};


/*!
 * \brief init ring appender
 * 
 * \return                  pointer to new format definition, NULL upon error
 */
sAppenderPlugin *zlogRing_Init( void )
{
    return( &structRing );
}


/*!
 * \brief check parameters for ring appender
 * 
 * \param   params          parameter string
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int ringCheck( char *params )
{
    if( params == NULL || *params == '\0' || atoi( params ) <= 0 ) {
        return( ZLOG_E_PARAMETERS );
    }
    return( ZLOG_NO_ERROR );
}


/*!
 * \brief open ring appender
 * 
 * \param   pApp            pointer to appender
 * \param   params          pointer to parameters
 * 
 * \return                  error code: 0=ok, <0=error
 */
static int ringOpen( sAppender *pApp )
{
    sRing   *pRing;
    char    *ptr;
    int     size;
    
    // destroy ring if it already exists (re-open)
    if( pApp->channel != NULL ) {
        ringClose( pApp );
    }
    
    size = atoi( pApp->parameters ) << 10;      // size is in kilobytes
    
    // allocate memory for control structure and ring buffer
    pRing = malloc( sizeof( sRing ));
    if( pRing == NULL ) {
        return(  ZLOG_E_CHANNEL );
    }
    ptr = malloc( size + strlen( MAGIC_RINGBUFFER_TAG_1 ) + strlen( MAGIC_RINGBUFFER_TAG_2 ) +1 );
    if( ptr == NULL ) {
        free( pRing );
        return(  ZLOG_E_CHANNEL );
    }
    
    // initialise structure
    pRing->buffer = ptr + strlen( MAGIC_RINGBUFFER_TAG_1 );
    pRing->head = pRing->buffer;
    pRing->tail = pRing->buffer;
    pRing->end  = pRing->buffer + size;
    pRing->size = size;
    *(pRing->end) = '\0';
        
    memcpy( pRing->_magic, MAGIC_RING, MAGIC_MAX_LENGTH );
    memcpy( pRing->_magic2, MAGIC_RING, MAGIC_MAX_LENGTH );
    memcpy( ptr, MAGIC_RINGBUFFER_TAG_1, strlen( MAGIC_RINGBUFFER_TAG_1 ));
    memcpy( pRing->end +1, MAGIC_RINGBUFFER_TAG_2, strlen( MAGIC_RINGBUFFER_TAG_2 ));
    memset( pRing->buffer, 0xff, size );
    
    pApp->channel = (void *)pRing;
    
    return( ZLOG_NO_ERROR );
}


static int ringClose( sAppender *pApp )
{
    sRing   *pRing;
    
    pRing = (sRing *)pApp->channel;
    if( pRing != NULL ) {
        free( pRing->buffer - strlen( MAGIC_RINGBUFFER_TAG_1 ));
        free( pRing );
        pApp->channel = NULL;
    }
    return( ZLOG_NO_ERROR );
}


static int ringLog( sAppender *pApp, unsigned int level, char *message )
{
    sRing   *pRing;
    int     len;
    int     wraparound;
    
    if( (pRing = pApp->channel) != NULL ) {
        len = strlen( message ) +1;         // include '\0'
        wraparound = ((pRing->tail + len) >= pRing->end) ? 1 : 0;
        
        if( pRing->tail >= pRing->head && wraparound == 0 ) {
            memcpy( pRing->tail, message, len );
            pRing->tail += len;
        } else {
            if( wraparound == 1 ) {
                memcpy( pRing->tail, message, pRing->end - pRing->tail );
                memcpy( pRing->buffer, &message[pRing->end - pRing->tail], len - (pRing->end - pRing->tail) );
                pRing->tail = pRing->buffer + len - (pRing->end - pRing->tail);
                pRing->head = pRing->buffer;
            } else {
                memcpy( pRing->tail, message, len );     // include '\0'
                pRing->tail += len;
            }
            if( pRing->tail >= pRing->head ) {
                // advance head if old entry partly overwritten
                pRing->head = (pRing->tail < (pRing->end -1)) ? pRing->tail +1 : pRing->buffer;
                while( *pRing->head != '\0' ) {
                    pRing->head++;
                    if( pRing->head >= pRing->end ) pRing->head = pRing->buffer;
                }
                pRing->head++;
                if( pRing->head >= pRing->end ) pRing->head = pRing->buffer;
            }
        }
        return( ZLOG_NO_ERROR );
    }
    
    return( ZLOG_E_CHANNEL );
}


/*!
 * \brief Dump contents of ring to appender
 * 
 * \param       aRing               pointer to ring appender
 * \param       aOut                pointer to output appender
 * 
 * \result                          -
 */
void ringDump( sAppender *aRing, sAppender *aOut )
{
    sRing   *pRing;
    char    *line;
    
    if( (pRing = aRing->channel) != NULL ) {
        line = pRing->head;
        if( pRing->tail < pRing->head ) {
            // must wraparound
            while( line < pRing->end ) {
                (*aOut->plugin->log)( aOut, zlogLevelDebug, line );
                line += strlen( line ) +1;
            }
            line = pRing->buffer;
        }
        while( line < pRing->tail ) {
            (*aOut->plugin->log)( aOut, zlogLevelDebug, line );
            line += strlen( line ) +1;
        }
        pRing->head = pRing->buffer;
        pRing->tail = pRing->buffer;
    }
}

/*!
 * \endcond
 */
/*! @} */
