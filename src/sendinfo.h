

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
