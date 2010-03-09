/*
 * common functions for samples
 * 
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
 */
 
#ifndef MYLIB_H_
#define MYLIB_H_

/*
 * function declarations
 */
extern int          getpassword( char *pwd );
extern char         *hexdump( void *string, int len, int spaces );
extern char         *deltatime( uint32_t seconds );
extern char         *ip_addr( uint32_t ip );
extern void         Shutdown( int arg );

#endif /*MYLIB_H_*/
