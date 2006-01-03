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
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/in.h> //IPPROTO
#include <arpa/inet.h> //inet_pton
#include <string.h> //memset
#include <net/if.h> //map interface to index
#include "sendinfo.h"
#include "packet_buffer.h"
#include "config.h"



#define SIN6_LEN //required for compile-time tests

void 	__P(check(char *msg, int c));
u_int16_t 	__P(tcp_checksum());
void 			__P(set_payload());
void 			__P(check_warning());
typedef int sock_descriptor_t;





void set_tcpsockopts(packet_buffer_t *sendinfo, config_t *conf){
	tcpconf_t* tcpconf = conf->trans_proto;
	int ret;
	sendinfo->proto = PROTO_TCP;
	
	/* save payload into buffer */
	packet_buffer_t *buffer = (sendinfo);

	set_payload(buffer->data_ptr, tcpconf->payload_size, tcpconf->pfile, 0);
	buffer->data_size += tcpconf->payload_size;
	
	ret = setsockopt(*sendinfo->fd, IPPROTO_TCP, TCP_MAXSEG, &tcpconf->mss, sizeof(int));
	check_warning("WARNING TCP mss option", ret);
	ret = setsockopt(*sendinfo->fd, IPPROTO_TCP, TCP_NODELAY, &tcpconf->nodelay, sizeof(int));
	check_warning("WARNING TCP nodelay option", ret); 	
}




void init_tcpsocket(sock_descriptor_t *fd, config_t *conf){
	int ret;
	int one = 1;
	struct sockaddr_in dst_addr;
	struct sockaddr_in src_addr;

	ip4conf_t *ipconf;
	tcpconf_t *tcpconf;

	ipconf = (ip4conf_t*)conf->net_proto;
	tcpconf = (tcpconf_t*)conf->trans_proto;

	*fd = socket(PF_INET, SOCK_STREAM, 0);
	check("tcp socket", *fd);
	
	ret = setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("tcp setsockopt(SO_REUSEADDR)", ret);
	
	
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(tcpconf->dport);
	inet_aton(ipconf->dst, &dst_addr.sin_addr);
	memset(&dst_addr.sin_zero, '0', 8);

	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons(tcpconf->sport);
	inet_aton(ipconf->src, &src_addr.sin_addr);
	memset(&src_addr.sin_zero, '0', 8);

	ret = bind(*fd, (struct sockaddr*)&src_addr, sizeof(struct sockaddr));
	check("tcp bind", ret);

	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));
	check("tcp connect", ret);
}



void init_tcpip6socket(sock_descriptor_t *fd, config_t *conf){

	int ret;
	int one = 1;
	struct sockaddr_in6 dst_addr;
	struct sockaddr_in6 src_addr;
	
	
	ip6conf_t *ipconf;
	tcpconf_t *tcpconf;
	
	ipconf = (ip6conf_t*)conf->net_proto;
	tcpconf = (tcpconf_t*)conf->trans_proto;
	
	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	check("tcp socket", *fd);
	
	ret = setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("tcp setsockopt(SO_REUSEADDR)", ret);
	
	dst_addr.sin6_family = AF_INET6;
	dst_addr.sin6_port = htons(tcpconf->dport);
	inet_pton(AF_INET6, ipconf->dst, &dst_addr.sin6_addr);
	dst_addr.sin6_flowinfo = 0;
  /*  dst_addr.sin6_scope_id = if_nametoindex("eth0"); */
     dst_addr.sin6_scope_id = if_nametoindex(ipconf->interface); 	
	
	src_addr.sin6_family = AF_INET6;
	src_addr.sin6_port = htons(tcpconf->sport);
	inet_pton(AF_INET6, ipconf->src, &src_addr.sin6_addr);
	src_addr.sin6_flowinfo = 0;
	

	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	check("tcp connect", ret);
}





/* Interface for set_tcphdr */
void fill_tcphdr(packet_buffer_t *sendinfo, config_t *conf) {
	tcpconf_t *tcpconf = conf->trans_proto;
	packet_buffer_t *buffer = (sendinfo);
	struct tcphdr *tcph;

	
	tcph = (struct tcphdr*) p_buf_get_data_ptr(buffer, tcpconf->off * 4);

	tcph->th_sport = htons(tcpconf->sport);
	tcph->th_dport = htons(tcpconf->dport);
	tcph->th_seq = htonl(tcpconf->seq);
	tcph->th_ack = htonl(tcpconf->ack);
	tcph->th_x2 = 0;
	tcph->th_off = tcpconf->off;
	tcph->th_win = htons(tcpconf->win);
	tcph->th_sum = 0;
	tcph->th_urp = htons(tcpconf->urp);

	/* tcp flags */
	if(tcpconf->FIN) tcph->th_flags = tcph->th_flags | TH_FIN;
	if(tcpconf->SYN) tcph->th_flags |= TH_SYN;
	if(tcpconf->RST) tcph->th_flags |= TH_RST;
	if(tcpconf->PUSH)tcph->th_flags |= TH_PUSH;
	if(tcpconf->ACK) tcph->th_flags |= TH_ACK;
	if(tcpconf->URG) tcph->th_flags |= TH_URG;
	
	//fprintf(stderr, "DEBUG_1\n");
	tcph->th_sum =  tcp_checksum(IPPROTO_TCP,
					 	  tcph,
					 	  buffer->data_size,	
					 	  *tcpconf->ip_dst_, 
					 	  *tcpconf->ip_src_) ;
					 	  	//fprintf(stderr, "DEBUG_2\n");

}

