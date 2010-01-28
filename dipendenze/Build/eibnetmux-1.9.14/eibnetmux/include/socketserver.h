/*
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2008 Urs Zurbuchen <going_nuts@users.sourceforge.net>
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
 * socket server client
 */
 
#ifndef EIBNETMUX_SOCKET_H_
#define EIBNETMUX_SOCKET_H_

#include <stdint.h>


/********************************/
/* Constants and structures     */
/********************************/

/**
 * configuration socket server
 **/
#define SOCKET_TCP_PORT                 4390
#define SOCKET_UNIX_PATH                "/tmp/eibnetmux"

#define SOCKET_NAME_MAX_LENGTH          64
#define SOCKET_PASSWORD_MAX_LENGTH      64


/**
 * error codes
 **/
#define E_NO_ERROR                      0x00
#define E_SOCKET_CLOSED                 0x01
#define E_NO_SOCKETS                    0x02
#define E_BAD_REQUEST                   0x03
#define E_CMD_UNKNOWN                   0x04
#define E_TIMEOUT                       0x05
#define E_UNAUTHORISED                  0x06
#define E_PASSWORD                      0x07
#define E_DHM                           0x08
#define E_PARAMETER                     0x09


/**
 * structures
 **/
typedef struct __attribute__((packed)) {
        uint8_t  cmd;
        uint16_t address;                       // group address or group address mask
} SOCKET_CMD_HEAD;

typedef struct __attribute__((packed)) {
        uint8_t  status;
        uint16_t size;                          // network byte order, also used for error code if status = SOCKET_STAT_ERROR
} SOCKET_RSP_HEAD;

/*
 * Socket commands
 */
#define SOCKET_API_VERSION      3               // increase if you change any of the socket commands or status

// used:        Aa Bb Cc D  E                 K  Ll M         p    Rr S        V  Ww X
// available:             d  e Ff Gg Hh Ii Jj  k     m Nn Oo P Qq     s Tt Uu  v     x Yy Zz 1234567890
#define SOCKET_CMD_KEY          'K'
#define SOCKET_CMD_DHM          'D'
#define SOCKET_CMD_AUTH         'A'
#define SOCKET_CMD_NAME         'a'
#define SOCKET_CMD_VERSION      'V'
#define SOCKET_CMD_READ         'R'
#define SOCKET_CMD_READ_ONCE    'r'
#define SOCKET_CMD_WRITE        'W'
#define SOCKET_CMD_WRITE_ONCE   'w'
#define SOCKET_CMD_MONITOR      'M'
#define SOCKET_CMD_PASSTHROUGH  'p'
#define SOCKET_CMD_EXIT         'X'
#define SOCKET_CMD_MGMT_CLIENT  'C'
#define SOCKET_CMD_MGMT_GETLOG  'l'
#define SOCKET_CMD_MGMT_SETLOG  'L'
#define SOCKET_CMD_MGMT_STATUS  'S'
#define SOCKET_CMD_MGMT_GETBLOCK 'b'
#define SOCKET_CMD_MGMT_SETBLOCK 'B'
#define SOCKET_CMD_MGMT_CLOSE   'c'

/*
 * access block levels
 */
#define SOCKET_BLOCK_DENY       1
#define SOCKET_BLOCK_READ       2
#define SOCKET_BLOCK_WRITE      3
#define SOCKET_BLOCK_ALL        4


/*
 * Socket status
 */
#define SOCKET_STAT_KEY         'K'
#define SOCKET_STAT_DHM         'D'
#define SOCKET_STAT_AUTH        'A'
#define SOCKET_STAT_NAME        'a'
#define SOCKET_STAT_VERSION     'V'
#define SOCKET_STAT_READ        'R'
#define SOCKET_STAT_WRITE       'W'
#define SOCKET_STAT_MONITOR     'M'
#define SOCKET_STAT_PASSTHROUGH 'p'
#define SOCKET_STAT_EXIT        'X'
#define SOCKET_STAT_ERROR       'E'
#define SOCKET_STAT_MGMT_CLIENT 'C'
#define SOCKET_STAT_MGMT_GETLOG 'L'
#define SOCKET_STAT_MGMT_SETLOG 'L'
#define SOCKET_STAT_MGMT_STATUS 'S'
#define SOCKET_STAT_MGMT_GETBLOCK 'b'
#define SOCKET_STAT_MGMT_SETBLOCK 'B'
#define SOCKET_STAT_MGMT_CLOSE  'c'

#endif /*EIBNETMUX_SOCKET_H_*/
