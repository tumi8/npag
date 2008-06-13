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

int set_payload	__P((char *buf, int size, char *filename, int format, int pos));

typedef struct protocol_functions {
	void (*set_nethdr)(packet_buffer_t*, config_t*);
	void (*set_transhdr)(packet_buffer_t*, config_t*);
	void (*init_socket) (sock_descriptor_t *fd, config_t *conf);
     void (*rand_hdr)(packet_buffer_t*);
} protofunc_t;


typedef struct adhdr {
	int payload_size;
	struct timeval tv;
	int seq;

	unsigned short mysize;
}adhdr_t;


typedef struct thread_param {
	config_t *conf;
	int id;
}thread_param_t;



void set_nethdr_NOT_DEFINED		__P(());
void set_transhdr_NOT_DEFINED	__P(());
void init_socket_NOT_DEFINED	__P(());
void sectotv				__P((double sec, struct timeval *tv));
void wait_timeval			__P((struct timeval *tv));
void wait_timeval_ext		__P((struct timeval *, struct timeval *));
void init_generator			__P((protofunc_t *gen, config_t *conf));
void send_raw				__P((packet_buffer_t*, config_t*, protofunc_t*, int));
void send_kernel			__P((packet_buffer_t*, config_t*, protofunc_t*, int));
void init_sendinfo			__P((packet_buffer_t *sendinfo));
void empty_buffer		__P((packet_buffer_t *buffer));
int dec_available_buffer		__P((packet_buffer_t *buffer, int decrease_size));



extern int verbose;
extern int num_of_threads;
extern FILE *output;
extern int out;
extern pthread_cond_t master_wait;

pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MUTEX_LOCK(_P_) if (pthread_mutex_lock(&_P_)) { \
   			 perror("pthread_mutex_lock"); \
   			 pthread_exit(NULL); \
			} ;


#define MUTEX_UNLOCK(_P_) if(pthread_mutex_unlock(&_P_)) { \
  			  perror("pthread_mutex_unlock"); \
   			 pthread_exit(NULL); \
			};
