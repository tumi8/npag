/*
 * This file is part of
 * npag - Network Packet Generator
 * Copyright (C) 2005 Christian Bannes, University of Tübingen,
 * Germany
 * 
 * npag is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 * MA  02110-1301, USA.
 */

enum proto {PROTO_TCP, PROTO_UDP};
/*
#ifndef PACKET_BUFFER_H
#include "packet_buffer.h"
#endif
*/

/*
 * Information needed to send a packet:
 * 1. a socket descriptor
 * 2. ancillary data for ip header specification
 * 3. the packet which might contain the header (in case of raw sockets)
 *
 */
 /*
typedef struct sendinfo {
	int *fd; 
	struct msghdr msg;	
//	struct s_cksuminfo cksuminfo;
	packet_buffer_t p_buf;
//	u_int16_t *udp_length;
}sendinfo_t;

*/
