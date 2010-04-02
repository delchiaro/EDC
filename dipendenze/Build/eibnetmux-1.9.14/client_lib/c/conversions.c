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
 *   \brief Utility functions for conversions
 * \endif
 */

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>

#include "enmx_lib.private.h"


/*
 * local functions
 */
static unsigned int     _enmx_eis2value( int eis, unsigned char *datastream, int length, void *value );


/*!
 * \addtogroup xgUtil
 * @{
 */

/*!
 * \brief Variable sizes for EIS types
 * 
 * Client application developers can use the following table to determine the
 * minimum buffer size required to convert KNX data to a C variable.
 * 
 * Retrieve the size as:
 * \code
 *      enmx_EISsizeC[eis]
 * \endcode
 * where 'eis' stands for the EIS number.
 */
int enmx_EISsizeC[16] = { -1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 1, 4, 15 };


/*!
 * \brief Buffer sizes for EIS types
 * 
 * Client application developers can use the following table to determine the
 * minimum buffer size required to convert a C variable to a KNX data stream.
 * 
 * Retrieve the size as:
 * \code
 *      enmx_EISsizeKNX[eis]
 * \endcode
 * where 'eis' stands for the EIS number.
 */
int enmx_EISsizeKNX[16] = { -1, 1, 1, 4, 4, 3, 2, 1, 1, 5, 3, 5, 5, 2, 2, 15 };


/*!
 * \brief Convert KNX data stream - as returned by enmx_read() - to C variable
 * 
 * Requests sent on the KNX bus have no indication as to how its data should
 * be interpreted. Knowledge of the data format is part of the KNX group
 * definition or assignment, respectively. It is expressed as the EIS
 * (EIB Interchange Standard), a number in the range of 1-15 which defines
 * the data type.
 * 
 * Given the correct EIS, this function allows to easily convert the data
 * part of a KNX request to a C variable which then can be used for further
 * calculations or displaying.
 * 
 * ATTENTION:
 *      Caller must ensure that buffer is large enough to hold result
 *      See enmx_EISsizeC[].
 * 
 * \param   eis             EIS type (range 1-15)
 * \param   datastream      pointer to KNX data stream as returned by enmx_read()
 * \param   length          length of KNX data stream
 * \param   value           pointer to the buffer receiving the converted result
 * 
 * \return                  number indicating type of result (-1: error, 0: integer, 1: float: 2: char, 3:string)
 */
unsigned int enmx_eis2value( int eis, unsigned char *datastream, int length, void *value )
{
    return( _enmx_eis2value( eis, datastream, length, value ));
}


/*!
 * \brief Extract data from CEMI frame - as returned by enmx_monitor() - and convert to C variable
 * 
 * Requests sent on the KNX bus have no indication as to how its data should
 * be interpreted. Knowledge of the data format is part of the KNX group
 * definition or assignment, respectively. It is expressed as the EIS
 * (EIB Interchange Standard), a number in the range of 1-15 which defines
 * the data type.
 * 
 * Given the correct EIS, this function allows to easily convert the data
 * part of a KNX request to a C variable which then can be used for further
 * calculations or displaying.
 * 
 * ATTENTION:
 *      Caller must ensure that buffer is large enough to hold result
 *      See enmx_EISsizeC[].
 * 
 * \param   eis             EIS type (range 1-15)
 * \param   cemiframe       pointer to CEMIFRAME as returned by enmx_monitor()
 * \param   value           pointer to the buffer receiving the converted result
 * 
 * \return                  number indicating type of result (-1: error, 0: integer, 1: float: 2: char, 3:string)
 */
unsigned int enmx_frame2value( int eis, void *cemiframe, void *value )
{
    CEMIFRAME   *cemi;
    
    cemi = (CEMIFRAME *)cemiframe;
    return( _enmx_eis2value( eis, &cemi->apci, cemi->length, value ));
}


/*!
 * \if DeveloperDocs
 * \brief Internal conversion function (KNX to C)
 * 
 * See enmx_ei2value() for a detailed description.
 * 
 * \param   eis             EIS type (range 1-15)
 * \param   datastream      pointer to KNX data stream
 * \param   length          length of KNX data stream
 * \param   value           pointer to the buffer receiving the converted result
 * 
 * \return                  number indicating type of result (-1: error, 0: integer, 1: float: 2: char, 3:string)
 * \endif
 */
static unsigned int _enmx_eis2value( int eis, unsigned char *datastream, int length, void *value )
{
    enmx_KNXTypes   type = enmx_KNXerror;
    int             *number;
    double          *real;
    struct tm       cdate;
    float           fp_num;
    int             year;
    int             sign;
    int             exponent;
    int             mantissa;
    
    if( eis < 1 || eis > 15 || value == NULL || datastream == NULL ) {
        return( enmx_KNXerror );
    }
    number = value;
    real = value;
    switch( eis ) {
        case 1:
        case 7:
            *number = *datastream & 0x01;
            type = enmx_KNXinteger;
            break;
        case 2:
            *number = *datastream & 0x07;
            *number *= (*datastream & 0x08) ? -1 : 1;
            type = enmx_KNXinteger;
            break;
        case 8:
            *number = *datastream & 0x03;
            type = enmx_KNXinteger;
            break;
        case 3:
            *number = (datastream[1] & 0x1f) * 3600 + (datastream[2] & 0x1f) * 60 + (datastream[3] & 0x3f);
            type = enmx_KNXinteger;
            break;
        case 4:
            // years since 1900
            if( datastream[3] >= 90 ) {
                    year = datastream[3] & 0x7f;
            } else {
                    year = (datastream[3] & 0x7f) + 100;
            }
            cdate.tm_year = year;
            cdate.tm_mon  = (datastream[2] & 0x0f) -1;
            cdate.tm_mday = datastream[1] & 0x1f;
            cdate.tm_hour = 0;
            cdate.tm_min  = 0;
            cdate.tm_sec  = 0;
            *number = mktime( &cdate );
            type = enmx_KNXinteger;
            break;
        case 5:
            sign     = ((datastream[1] & 0x80) == 0) ? 0 : 1;
            exponent = (datastream[1] & 0x78) >> 3;
            mantissa = ((datastream[1] & 0x07) << 8) | datastream[2];
            if( sign ) mantissa = mantissa - 2048;
            *real = mantissa * 0.01 * pow( 2, exponent );
            type = enmx_KNXfloat;
            break;
        case 6:
        case 13:
        case 14:
            *number = datastream[1] & 0xff;
            type = enmx_KNXinteger;
            break;
        case 9:
            memcpy( &fp_num, datastream +1, 4 );
            *real = fp_num;
            type = enmx_KNXfloat;
            break;
        case 10:
            *number = (datastream[1] << 8) | datastream[2];
            type = enmx_KNXinteger;
            break;
        case 11:
            *number = (datastream[1] << 24) | (datastream[2] << 16) | (datastream[3] << 8) | datastream[4];
            type = enmx_KNXinteger;
            break;
        case 12:
        case 15:
            memcpy( value, datastream +1, length );
            type = enmx_KNXstring;
            break;
    }
    
    return( type );
}


/*!
 * \brief Convert C variable to KNX data stream
 * 
 * Requests sent on the KNX bus have no indication as to how its data should
 * be interpreted. Knowledge of the data format is part of the KNX group
 * definition or assignment, respectively. It is expressed as the EIS
 * (EIB Interchange Standard), a number in the range of 1-15 which defines
 * the data type.
 * 
 * Given the correct EIS, this function allows to easily create the data
 * part of a KNX request from a C variable. The result can be used directly
 * for enmx_write().
 * 
 * ATTENTION:
 *      Caller must ensure that buffer is large enough to hold result.
 *      See enmx_EISsizeKNX[].
 * 
 * \param   eis             EIS type (range 1-15)
 * \param   value           pointer to the buffer containing the C variable
 * \param   datastream      pointer to the buffer receiving the converted result
 * 
 * \return                  0: ok, -1: error
 */
int enmx_value2eis( int eis, void *value, unsigned char *datastream )
{
    uint32_t        number, *p_number;
    double          real, *p_real;
    struct tm       ltime;
    time_t          datetime;
    
    if( eis < 1 || eis > 15 || value == NULL || datastream == NULL ) {
        return( -1 );
    }
    
    datastream[0] = 0;
    p_number = (uint32_t *)value;
    p_real = (double *)value;
    switch( eis ) {
        case 1:
        case 7:
            number = *p_number;
            datastream[0] = number & 0x01;
            break;
        case 2:
            number = *p_number;
            datastream[0] = number & 0x0f;
            if( number >= 128 ) datastream[0] |= 0x08;
            break;
        case 3:     // time
            datetime = *p_number;
            localtime_r( &datetime, &ltime );
            datastream[0] = 0;
            datastream[1] = ltime.tm_hour + (((ltime.tm_wday == 0) ? 7 : ltime.tm_wday) << 5);
            datastream[2] = ltime.tm_min;
            datastream[3] = ltime.tm_sec;
            break;
        case 4:     // date
            datetime = *p_number;
            localtime_r( &datetime, &ltime );
            if( ltime.tm_year < 90 ) {
                // KNX does not know any date before 01/01/1990
                return( -1 );
            } else {
                datastream[1] = ltime.tm_mday;
                datastream[2] = ltime.tm_mon +1;
                if( ltime.tm_year < 100 ) {
                    // 01/01/1990 - 31/12/1999
                    datastream[3] = ltime.tm_year;
                } else {
                    // 01/01/2000 - 31/12/2089
                    datastream[3] = ltime.tm_year - 100;
                }
            }
            datastream[0] = 0;
            break;
        case 5:
            return( -1 );
            break;
        case 11:
            number = *p_number;
            number = htonl( number );
            memcpy( &datastream[1], &number, 4 );
            break;
        case 9:
            real = *p_real;
            memcpy( &datastream[1], &real, 4 );
            break;
        case 6:
        case 12:
        case 13:
        case 14:
            number = *p_number;
            datastream[1] = (unsigned char)(number & 0xff);
            break;
        case 10:
            number = *p_number;
            number = htons( number );
            memcpy( &datastream[1], &number, 2 );
            break;
        case 8:
            number = *p_number;
            datastream[0] = number & 0x03;
            break;
        case 15:
            memcpy( &datastream[1], value, enmx_EISsizeKNX[eis] );
            break;
    }
    
    return( 0 );
}


/*!
 * \brief Convert KNX group address to ENMX_ADDRESS
 * 
 * The KNX bus and, consequently, this library use a 16-bit integer
 * to address a specific group. The value is formatted as follows:
 * \code
 *      0mmm msss gggg gggg
 * \endcode
 * where
 * -     m = maingroup
 * -     s = subgroup
 * -     g = group
 * 
 * This function converts a human-readable KNX group address of the form "x/y/z"
 * to the 16-bit integer ENMX_ADDRESS.
 * 
 * \param   KNXgroup        group address, string in the form "x/y/z"
 * 
 * \return                  ENMX_ADDRESS or -1 in case of an error
 */
ENMX_ADDRESS enmx_getaddress( const char *KNXgroup )
{
    int         maingroup, subgroup, group;
    const char  *ptr;
    
    // get maingroup
    ptr = KNXgroup;
    maingroup = 0;
    while( *ptr && isdigit( *ptr )) {
        maingroup *= 10;
        maingroup += *ptr - '0';
        ptr++;
    }
    if( *(ptr++) != '/'  ) {
        return( -1 );
    }
    
    // get subgroup
    subgroup = 0;
    while( *ptr && isdigit( *ptr )) {
        subgroup *= 10;
        subgroup += *ptr - '0';
        ptr++;
    }
    if( *(ptr++) == '\0' ) {
        return( -1 );
    }
    
    // get group
    group = 0;
    while( *ptr && isdigit( *ptr )) {
        group *= 10;
        group += *ptr - '0';
        ptr++;
    }
    if( *ptr != '\0' ) {
        return( -1 );
    }
    
    // calculate address
    return( ((maingroup & 0x0f) << 11) | ((subgroup & 0x07) << 8) | (group & 0xff) );
}


/*!
 * \brief Convert KNX group address to string
 * 
 * The KNX bus and, consequently, this library use a 16-bit integer
 * to address a specific group. The value is formatted as follows:
 * \code
 *      0mmm msss gggg gggg
 * \endcode
 * where
 * -     m = maingroup
 * -     s = subgroup
 * -     g = group
 * 
 * This function converts a 16-bit integer ENMX_ADDRESS into a
 * human-readable KNX group address of the form "x/y/z".
 * 
 * ATTENTION:
 *      caller has to release returned buffer
 * 
 * \param   knxaddress      encoded KNX group address
 * 
 * \return                  string containing KNX group address or NULL upon error
 */
char *enmx_getgroup( ENMX_ADDRESS knxaddress )
{
    int     maingroup, subgroup, group;
    char    *ptr;
    
    // extract values
    maingroup = (knxaddress >> 11) & 0x0f;
    subgroup = (knxaddress >> 8) & 0x07;
    group = knxaddress & 0xff;
    
    // allocate buffer for xx/y/zzz
    if( (ptr = malloc( 9 )) == NULL ) {
        return( NULL );
    }
    
    sprintf( ptr, "%d/%d/%d", maingroup, subgroup, group );
    return( ptr );
}
/*! @} */
