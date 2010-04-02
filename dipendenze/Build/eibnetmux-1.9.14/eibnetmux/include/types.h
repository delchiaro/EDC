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
 */
 
#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>

#include <pth.h>

/*
 * enum constants
 */
typedef enum _eShutdownCallbacks {
        shutdownHTTP,
        shutdownEIBnetServer,
        shutdownEIBnetClient,
        shutdownSocketServer,
        shutdownEIBDServer,
        shutdownEntries                 // must always be last item in this enum
} eShutdownCallbacks;


/*
 * typedefs
 */
typedef unsigned char           boolean;


/*
 * structure definitions
 */
typedef struct {
        void      (*func)( void );
        uint8_t   flag;
} sShutdownHandlers;

typedef struct {
        pth_message_t   pth_msg;
        uint8_t         command;
} sMessage;

#endif /*TYPES_H_*/
