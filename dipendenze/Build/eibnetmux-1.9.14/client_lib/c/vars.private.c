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
 *   \brief Library-internal (private) global variables
 * \endif
 */

#include "enmx_lib.private.h"
 
/*!
 * \addtogroup xgSetup
 * @{
 */

/*!
 * \cond DeveloperDocs
 */
/*!
 * \brief Linked-list of currently active connections
 */
sConnectionInfo *enmx_connections = 0;

/*!
 * \if DeveloperDocs
 * \brief Library state
 * \endif
 */
int     enmx_mode = ENMX_LIB_UNDEFINED;



/*!
 * \endcond
 */
/*! @} */
