
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







