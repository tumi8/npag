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

#include <stdlib.h>
#include <stdio.h>

#ifndef PACKET_BUFFER_H
#include "packet_buffer.h"
#endif



char* p_buf_get_data_ptr(packet_buffer_t *p_buf, int size) {
	
	if(p_buf->data_size + size > p_buf->allocated_space)
		return NULL;
	
	p_buf->data_ptr -= size;
	p_buf->data_size += size;
	
	
	return p_buf->data_ptr;
}



int p_buf_move_data_ptr(packet_buffer_t *p_buf, int decrease_size) {

	if(p_buf->data_size < decrease_size) return -1;
	
	p_buf->data_ptr += decrease_size;
	p_buf->data_size -= decrease_size;
	
	return 1;
}


void p_buf_empty(packet_buffer_t *p_buf) {
	p_buf->data_size = 0;
	p_buf->data_ptr = p_buf->border + p_buf->allocated_space;	
}







