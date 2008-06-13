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

#define _BSD_SOURCE

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h> //malloc
#include <sys/socket.h>
#include <string.h> //memset

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <arpa/inet.h> //inet_aton
#include <sys/uio.h> //struct iovec

#include <sys/time.h>
#include <unistd.h> //get_pid

 
#ifndef PACKET_BUFFER_H
#include "packet_buffer.h"
#endif

#include "memory.h"
#include "config.h"
#include "sendinfo.h"
#include "protokol.h"
typedef int sock_descriptor_t;

#include "tcp_module.h"
#include "udp_module.h"
#include "icmp_module.h"
#include "ip_module.h"


#include "sender.h"

 void send_raw_2(packet_buffer_t *sendinfo, config_t *conf,  protofunc_t *gen, int th_id);
 void send_traffic();
 void sender_init();


typedef struct sender {
	void (*init)();
	void (*set_buf)();
	int (*send)();
	void (*leave)();	
    void (*rand_hdr)();
	
	/* it would be nicer to realize these variables as globals because 
	   nearly every function is using them. The problem is that globals are 
	   shared among threads but these variables are thread specific */
	struct msghdr msgh;
	struct iovec msg_iov;
	int hdr_buf_size;
	adhdr_t ah;
	int udp_seq;
	char sndbuf[65536];
	struct timeval tv, delay_tv;
}sender_t;

void raw_init(packet_buffer_t *p_buf, config_t* conf, protofunc_t *gen,  sender_t *sender) {
   struct sockaddr_in *dst_addr = NULL;
	sender->msgh.msg_name = (struct sockaddr*)dst_addr; /* destination address */
	sender->msgh.msg_namelen = 0;  /* address length */  
	sender->msgh.msg_iov = &sender->msg_iov;		     /* message buffer */
	sender->msgh.msg_iovlen = 1;			     /* number of message buffers */
	sender->msgh.msg_control = p_buf->msg.msg_control;
	sender->msgh.msg_controllen = p_buf->msg.msg_controllen;;
	sender->msgh.msg_flags = 0;
}


void kernel_init(packet_buffer_t *p_buf, config_t *conf, protofunc_t *gen, sender_t *sender) {
	//adhdr_t *ah = (adhdr_t*) param;
	
	//protofunc_t *gen = (protofunc_t*)param;
		sender->udp_seq = 2;
		gen->set_transhdr(p_buf, conf);
		 gen->set_nethdr(p_buf, conf);
		sender->hdr_buf_size = p_buf->data_size; 
	
	 struct sockaddr_in *dst_addr = NULL;
	sender->msgh.msg_name = (struct sockaddr*)dst_addr; /* destination address */
	sender->msgh.msg_namelen = 0;  /* address length */  
	sender->msgh.msg_iov = &sender->msg_iov;		     /* message buffer */
	sender->msgh.msg_iovlen = 1;			     /* number of message buffers */
	
	sender->msgh.msg_control = p_buf->msg.msg_control;
	sender->msgh.msg_controllen = p_buf->msg.msg_controllen;;
	sender->msgh.msg_flags = 0;

	
	if(p_buf->proto == PROTO_UDP) {
		sender->ah.mysize = sizeof(int) * 2 + sizeof(struct timeval);
		
	 	sender->msg_iov.iov_len =  sender->ah.mysize;
	 	sender->ah.seq = 0;
	 	sender->msg_iov.iov_base = &sender->ah;
	 	sendmsg(*p_buf->fd,&sender->msgh, 0  );
	}
		
	else if (p_buf->proto == PROTO_TCP) {
		sender->ah.mysize = sizeof(int) + sizeof(struct timeval);
	}
}



//void raw_set_buf(packet_buffer_t *buffer, pattern_t *pattern, config_t *conf, protofunc_t *gen, packet_buffer_t *p_buf, sender_t *sender) {
void raw_set_buf(packet_buffer_t *buffer, pattern_t *pattern, config_t *conf, protofunc_t *gen, packet_buffer_t *p_buf, sender_t *sender) {
		  
//		  p_buf_empty(buffer);
		  p_buf_empty(p_buf);

			/* set payload */

		//	set_payload(p_buf_get_data_ptr(buffer, pattern->payload_size), pattern->payload_size, pattern->payload_file, pattern->file_format, 0);
			set_payload(p_buf_get_data_ptr(p_buf, pattern->payload_size), pattern->payload_size, pattern->payload_file, pattern->file_format, 0);
		
			gen->set_transhdr(p_buf, conf);
			gen->set_nethdr(p_buf, conf);
	
			sender->msgh.msg_control = p_buf->msg.msg_control;
			sender->msgh.msg_controllen = p_buf->msg.msg_controllen;;

			sender->msg_iov.iov_len = p_buf->data_size;
}

void kernel_set_buf(packet_buffer_t *buffer, pattern_t *pattern, config_t *conf, protofunc_t *gen, packet_buffer_t *p_buf, sender_t *sender) {
			
			
			int buf_size;
	
			if(p_buf->data_size > sender->hdr_buf_size) {
				p_buf_move_data_ptr(p_buf, (p_buf->data_size - sender->hdr_buf_size));	
			}
			
			set_payload(p_buf_get_data_ptr(p_buf, pattern->payload_size), pattern->payload_size, pattern->payload_file, pattern->file_format, 0);
			buf_size = p_buf->data_size * pattern->send_packets;
			buf_size += sender->ah.mysize * pattern->send_packets;
		
			sender->msg_iov.iov_len = p_buf->data_size + sender->ah.mysize;
}


int raw_send(config_t *conf, packet_buffer_t *p_buf, sock_descriptor_t fd, sender_t *sender) {
					int nbytes;
					
					sender->msg_iov.iov_base = p_buf->data_ptr;
					nbytes = sendmsg(fd,&sender->msgh, 0  );


                    // log output to a file
					if(out) {
						if(conf->net_proto_type == TYPE_IP6) {
							p_buf->data_size += 40;
							p_buf->data_ptr -= 40;
						}
						unsigned char val;
						char str[2];
						int ii;
						for(ii = 0; ii < p_buf->data_size; ++ii) {
							val = *(p_buf->data_ptr + ii);
							sprintf(str, "%x ", val);
							if(strlen(str) == 2) fputc('0', output);
							fputs(str, output);
						}
						fputs("\n\n", output);
						if(conf->net_proto_type == TYPE_IP6) {
							p_buf->data_size -= 40;
							p_buf->data_ptr += 40;	
						}
					} /* endif(out) */
					
					//if(verbose > 1)
					//	printf("%i: %i bytes written\n", th_id,nbytes);
				return nbytes;
}


struct my_param {
	char *sndbuf;
	int *udp_seq;
	adhdr_t *ah;	
};


int kernel_send(config_t *conf, packet_buffer_t *buffer, sock_descriptor_t fd, sender_t *sender) {

		int nbytes;
		memcpy(sender->sndbuf + sender->ah.mysize, buffer->data_ptr, buffer->data_size);
		sender->ah.payload_size = buffer->data_size + sender->ah.mysize;
		
 						gettimeofday(&sender->ah.tv, NULL);
						//ah->seq = *udp_seq++;
						sender->ah.seq = sender->udp_seq;
						sender->udp_seq += 1;
 						memcpy(sender->sndbuf, &sender->ah, sender->ah.mysize);

 						sender->msg_iov.iov_base = sender->sndbuf;
 						nbytes = sendmsg(*buffer->fd,&sender->msgh, 0  );
 						
 		return nbytes;
}


void kernel_leave(packet_buffer_t *p_buf, sender_t *sender) {
	struct timeval tv;
	if(p_buf->proto == PROTO_UDP) {
		fprintf(stdout, "UDP connection teardown...\n");
		fflush(stdout);
		
		sectotv(2.0, &tv);
		wait_timeval(&tv);
	 	
	 	sender->msg_iov.iov_len =  sender->ah.mysize;/* sizeof(struct udp_addhdr); */
	 	sender->ah.seq = sender->udp_seq; /*last sequence number (+1) that was sent */
	 	sender->msg_iov.iov_base = &sender->ah;
	 	sendmsg(*p_buf->fd,&sender->msgh, 0  );
	 	
	 	sectotv(2.0, &tv);
		wait_timeval(&tv);
	 	
	 	sender->ah.seq = 1;
	 	sender->msg_iov.iov_base = &sender->ah;
	 	sendmsg(*p_buf->fd,&sender->msgh, 0  );
	}
}

void sender_init(sender_t *sender, int kernel) {
	
	if(kernel == 0) {
		sender->init = raw_init;
		sender->set_buf = raw_set_buf;
		sender->send= raw_send;
		sender->leave = NULL;
	}
	else if(kernel == 1) {
		sender->init = kernel_init;
		sender->set_buf = kernel_set_buf;
		sender->send= kernel_send;
		sender->leave = kernel_leave;
	}	
}








void register_functions();
protofunc_t*  get_functions(int kernel, int trans_type, int net_type) ;
void set_functions(protofunc_t*, config_t*);
void reg_table_init();

void* exec_thread(void *p) {
	thread_param_t *th_param = p;
	config_t *conf = th_param->conf;
	int th_id = th_param->id;
	
	sender_t sender;

	packet_buffer_t p_buf;
	//protofunc_t gen = {set_nethdr_NOT_DEFINED, set_transhdr_NOT_DEFINED, init_socket_NOT_DEFINED};
	protofunc_t *gen;
	
	init_sendinfo(&p_buf);
	//init_generator(&gen, conf);
	
	//reg_table_init();
	//register_functions();
	
	gen = get_functions(conf->kernel_packet, conf->trans_proto_type, conf->net_proto_type);
	if(gen == NULL) {
		fprintf(stderr, "gen not initialized\n");	
		exit(0);
	}

	//gen.init_socket(sendinfo.fd, conf);
	 gen->init_socket(p_buf.fd, conf);
	//sender_init();
	
	if(conf->kernel_packet == FALSE) {
		//send_raw(&sendinfo, conf, &gen, th_id);
	
		sender_init(&sender, 0);
	}
	else {
		//send_kernel(&sendinfo, conf, &gen, th_id);
		sender_init(&sender, 1);
	}

    sender.rand_hdr = gen->rand_hdr;

	send_traffic(&sender, &p_buf, conf, gen, th_id);
	//send_raw_2(&sendinfo, conf, gen, th_id);
	/* TODO change this */
	return NULL;
}





void send_traffic(sender_t *sender, packet_buffer_t *p_buf, config_t *conf, protofunc_t *gen, int th_id) {

	int i, j, l;
	int nbytes;
	pattern_t *pattern;

	sock_descriptor_t fd = *p_buf->fd;
	traffic_t *traffic = &conf->traffic;

	sender->init(p_buf, conf, gen, sender);

    // we wanna have accurate starting time of data stream for statistics, so
    // let's see if the time was already initialized and init it ourselves
    if (!stat_starttime.tv_sec) gettimeofday(&stat_starttime, 0);

	for(l = 0; l < traffic->repeat + 1; l++) {
		pattern = traffic->pattern;
        struct timeval bursttime;
        if (gettimeofday(&bursttime, 0) != 0)
            perror("failed to call gettimeofday");
        while(pattern != NULL) {

            sectotv(pattern->delay, &sender->delay_tv);
            sender->set_buf(p_buf, pattern, conf, gen, p_buf, sender);

            for(j = 0; j < pattern->repeat + 1; ++j) {
                sender->tv = sender->delay_tv; /* tv is overwritten by wait_timeval in LINUX */
                i = 0;

                if(verbose)
                    fprintf(stdout,"Thread %i starts sending...\n",th_id);
                for(i = 0; i < pattern->send_packets; ++i) {

                    // modify packet with random variations
                    if (sender->rand_hdr) sender->rand_hdr(conf, p_buf, fd, sender);
                    // send packet to network
                    nbytes = sender->send(conf, p_buf, fd, sender);						
                    // collect statistics
                    stat_psentcount++;
                    stat_psentsize += nbytes;

                    if(nbytes == -1) perror("send");
                    if(verbose > 1)
                        printf("%i: %i bytes written\n", th_id,nbytes);
                }

                if(verbose)
                    fprintf(stdout,"Thread %i is waiting %f seconds\n",th_id, pattern->delay);

                wait_timeval_ext(&sender->tv, &bursttime); 	

            }/* repeat pattern */
            pattern = pattern->next;
				
		}/* next pattern */
		if(l  != traffic->repeat  && verbose > 0) 
			fprintf(stdout, "THREAD %i IS REPEATING THE TRAFFIC\n", th_id);
		
		
	}/* endfor traffic repeat */
	
		/* UDP connection teardown */
		if(sender->leave != NULL)
			sender->leave(p_buf, sender);
	
		if(verbose)
			fprintf(stdout,"Thread %i HAS FINISHED ITS WORK\n",th_id);
		
	num_of_threads--; //TODO I think I need a mutex lock here...	
	if(num_of_threads == 0) {
		pthread_cond_broadcast(&master_wait);
	}
}


void init_sendinfo(packet_buffer_t *p_buf) {
	p_buf->fd = cmalloc(sizeof(int));
	p_buf->border = cmalloc(sizeof(char) * 65536);
	p_buf->allocated_space = 65536;
	p_buf->data_size = 0;
	p_buf->data_ptr = p_buf->border + p_buf->allocated_space;
	
	p_buf->msg.msg_control = NULL;
	p_buf->msg.msg_controllen = 0;	
}



void check(char *msg, int c) {
	if(c < 0) {
		perror(msg);
		exit(0);
	}
}
void check_warning(char *msg, int c) {
	if(c < 0) {
		perror(msg);
	}
}



//*****************************************
// Timer functions *
//*****************************************
void tvadd(tsum, t0, t1)
	struct timeval *tsum, *t0, *t1;
{

	tsum->tv_sec = t0->tv_sec + t1->tv_sec;
	tsum->tv_usec = t0->tv_usec + t1->tv_usec;
	if (tsum->tv_usec > 1000000)
		tsum->tv_sec++, tsum->tv_usec -= 1000000;
}



void tvsub(tdiff, t1, t0)
	struct timeval *tdiff, *t1, *t0;
{

	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0)
		tdiff->tv_sec--, tdiff->tv_usec += 1000000;
}




void sectotv(double sec, struct timeval *tv) {
	long floor = (long)sec;
	tv->tv_sec = floor; 	
	tv->tv_usec = (sec - floor) * 1000 * 1000;
}



void wait_timeval(struct timeval *towait) 
{
  select(1, (fd_set *)0, (fd_set *)0, (fd_set *)0, (towait));
}

/**
 * sleeps until time lastburst+towait is reached
 */
void wait_timeval_ext(struct timeval *towait, struct timeval* lastburst) 
{
    static int cpu_warning_issued = 0;
    static int cpu_slowcycles = 0;
    // calculate time, when next burst should be started
    struct timeval endtime;
    endtime.tv_sec = towait->tv_sec + lastburst->tv_sec;
    endtime.tv_usec = towait->tv_usec + lastburst->tv_usec;
    if (endtime.tv_usec > 1000000) {
        endtime.tv_usec -= 1000000;
        endtime.tv_sec++;
    }
    struct timeval curtime;
    if (gettimeofday(&curtime, 0) != 0) perror("failed to call gettimeofday");
    struct timeval difftime;
    if (timeval_subtract(&difftime, &endtime, &curtime) == 1) {
        cpu_slowcycles++;
        // if the CPU is too slow, issue warning
        // but we wait a few packet bursts first, as the code needs to be loaded into the CPU's cache
        if (cpu_slowcycles>100 && !cpu_warning_issued) {
            cpu_warning_issued = 1;
            fprintf(stderr, "WARNING: CPU is too slow to send packets in time, no more warnings will be issued\n");
        }
    } else {
        //printf("difftime: %d sec, %d usec\n", difftime.tv_sec, difftime.tv_usec);
        select(1, (fd_set *)0, (fd_set *)0, (fd_set *)0, &difftime);
    }
    if (gettimeofday(lastburst, 0) != 0) perror("failed to call gettimeofday");
}
/*

void set_nethdr_NOT_DEFINED() {
	fprintf(stderr, "Internal error (s_generator): function set_nethdr not defined\n");
	exit(0);
}
void set_transhdr_NOT_DEFINED() {
	fprintf(stderr, "Internal error (s_generator): function set_trans not defined\n");
	exit(0);
}
void init_socket_NOT_DEFINED() {
	fprintf(stderr, "Internal error (s_generator): function init_socket not defined\n");
	exit(0);
}*/







 struct reg_node {
	int kernel;
	int trans_type;
	int net_type;

	
	void *net;
	void *trans;
	void *sock_init;
    void *rand_hdr;
	
	void *next; //next 	
}rnode_head;


void reg_table_init() {
	//fprintf(stderr, "initializing table...\n");
	rnode_head.next = NULL;	
}

void reg_proto(int kernel, int trans_type, int net_type, void *trans, void *net, void *sock_init, void *rand_hdr) {
	struct reg_node *rnode = &rnode_head;
	
	while(rnode->next != NULL) {
		rnode = rnode->next;
	}
	
	rnode->next = cmalloc(sizeof(struct reg_node));
	rnode = rnode->next;
	
	//fprintf(stderr, "inserting: kernel: %i, trans_type %i, net_type %i\n", kernel, trans_type, net_type);
	rnode->next = NULL;
	rnode->kernel = kernel;
	rnode->trans_type = 	trans_type;
	rnode->net_type = net_type;
	rnode->trans = trans;
	rnode->net = net;
	rnode->sock_init = sock_init;
    rnode->rand_hdr = rand_hdr;
}

protofunc_t*  get_functions(int kernel, int trans_type, int net_type) {
		struct reg_node *rnode = &rnode_head;
		protofunc_t *functions;
		functions = NULL;
		while(rnode != NULL) {
			if(rnode->kernel == kernel && rnode->trans_type == trans_type && rnode->net_type == net_type) {
					functions = cmalloc(sizeof(protofunc_t));
					functions->set_nethdr = rnode->net;
					functions->set_transhdr = rnode->trans;
					functions->init_socket = rnode->sock_init;
                    functions->rand_hdr = rnode->rand_hdr;
				//	fprintf(stderr, "function found\n");
				 	break;
			}
			rnode = rnode->next;	 		
		}
		//fprintf(stderr, "returning from get_functions...Params: kernel: %i, trans_type %i, net_type %i\n", kernel, trans_type, net_type);
		return functions;
}



void empty(packet_buffer_t p, config_t c) {
}


void register_functions() {
	
	/* registrations */
	
	/* kernel */
	reg_proto(1, TYPE_TCP, TYPE_IP4, set_tcpsockopts, set_ipsockopts, init_tcpsocket, NULL);
	reg_proto(1, TYPE_TCP, TYPE_IP6, set_tcpsockopts, set_ipsockopts, init_tcpip6socket, NULL);
	reg_proto(1,TYPE_UDP, TYPE_IP4, set_udpsockopts, set_ipsockopts, init_udpsocket, NULL);
	reg_proto(1, TYPE_UDP, TYPE_IP6, set_udpsockopts, set_ipsockopts, init_udpip6socket, NULL);
	
	/* raw */
	
	reg_proto(0, TYPE_TCP, TYPE_IP4, fill_tcphdr, fill_ip4hdr, init_rawsocket, rand_tcp);
	reg_proto(0, -1, TYPE_IP4, empty, fill_ip4hdr, init_rawsocket, NULL);
	reg_proto(0, TYPE_TCP, TYPE_IP6, fill_tcphdr, fill_ip6hdr, init_rawsocket6, NULL);
	reg_proto(0, TYPE_UDP, TYPE_IP4, fill_udphdr, fill_ip4hdr, init_rawsocket, NULL);
	reg_proto(0, TYPE_UDP, TYPE_IP6, fill_udphdr, fill_ip6hdr, init_rawsocket6, NULL);
	reg_proto(0, TYPE_ICMP, TYPE_IP4, fill_icmphdr, fill_ip4hdr, init_rawsocket, NULL);
	reg_proto(0, TYPE_ICMP6, TYPE_IP6, fill_icmp6hdr, fill_ip6hdr, init_rawsocket6, NULL);	
	

	//fprintf(stderr, "registration completed\n");
	//reg_proto(TYPE_IP6, TYPE_TCP, fill_iphdr, fill_tcphdr, init_rawsockets);
	
}



