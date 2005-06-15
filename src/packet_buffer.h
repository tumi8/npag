

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

