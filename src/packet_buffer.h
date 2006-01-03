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

#include <sys/socket.h> //struct msghdr

#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H
#endif

//enum proto {PROTO_TCP, PROTO_UDP};

typedef struct packet_buffer {
	char *data_ptr;
	int data_size;
	
	int allocated_space;
	char *border;
	
	int *fd; /* socket descriptor */
	struct msghdr msg;	/* ancilarry data */
	

	int proto;
}packet_buffer_t;




char* p_buf_get_data_ptr		__P((packet_buffer_t *p_buf, int size)) ;
int p_buf_move_data_ptr		__P((packet_buffer_t *p_buf, int decrease_size)) ;
void p_buf_empty					__P((packet_buffer_t *p_buf)) ;

