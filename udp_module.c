/*
 * This file is part of
 * npag - Network Packet Generator
 * Copyright (C) 2005 Christian Bannes, University of T�bingen,
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
#define __FAVOR_BSD
#include <stdint.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/udp.h>
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



void set_udpsockopts(packet_buffer_t* sendinfo, config_t *conf){
	udpconf_t* udpconf = conf->trans_proto;
	sendinfo->proto = PROTO_UDP;

		/* save payload into buffer */
	packet_buffer_t *buffer = (sendinfo);

	set_payload(buffer->data_ptr, udpconf->payload_size, udpconf->pfile, 0);
	buffer->data_size += udpconf->payload_size;
}


void init_udpsocket(sock_descriptor_t *fd, config_t *conf){
	int ret;
	int one = 1;
	struct sockaddr_in dst_addr;
	struct sockaddr_in src_addr;

	ip4conf_t *ipconf;
	udpconf_t *udpconf;

	ipconf = (ip4conf_t*)conf->net_proto;
	udpconf = (udpconf_t*)conf->trans_proto;

	*fd = socket(PF_INET, SOCK_DGRAM, 0);
	check("udp socket", *fd);
	
	ret = setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("udp setsockopt(SO_REUSEADDR)", ret);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(udpconf->dport);
	struct in_addr in = { ipconf->dst };
	dst_addr.sin_addr = in;
	memset(&dst_addr.sin_zero, '0', 8);

	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons(udpconf->sport);
	struct in_addr sin = { ipconf->src };
	src_addr.sin_addr = sin;
	memset(&src_addr.sin_zero, '0', 8);

	ret = bind(*fd, (struct sockaddr*)&src_addr, sizeof(struct sockaddr));
	check("udp bind", ret);

	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));
	check("udp connect", ret);
}



void init_udpip6socket(sock_descriptor_t *fd, config_t *conf){

	int ret;
	int one = 1;
	struct sockaddr_in6 dst_addr;
	struct sockaddr_in6 src_addr;
	
	
	ip6conf_t *ipconf;
	udpconf_t *udpconf;
	
	ipconf = (ip6conf_t*)conf->net_proto;
	udpconf = (udpconf_t*)conf->trans_proto;
	
	*fd = socket(AF_INET6, SOCK_STREAM, 0);
	check("udp socket", *fd);
	
	ret = setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check("udp setsockopt(SO_REUSEADDR)", ret);
	
	dst_addr.sin6_family = AF_INET6;
	dst_addr.sin6_port = htons(udpconf->dport);
	inet_pton(AF_INET6, ipconf->dst, &dst_addr.sin6_addr);
	dst_addr.sin6_flowinfo = 0;
    dst_addr.sin6_scope_id = if_nametoindex(ipconf->interface);
	
	
	src_addr.sin6_family = AF_INET6;
	src_addr.sin6_port = htons(udpconf->sport);
	inet_pton(AF_INET6, ipconf->src, &src_addr.sin6_addr);
	src_addr.sin6_flowinfo = 0;
	

	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	check("udp connect", ret);
}




void fill_udphdr(packet_buffer_t *sendinfo, config_t *conf) {
	udpconf_t *udpconf = conf->trans_proto;
	packet_buffer_t *buffer = (sendinfo);
	struct udphdr *udph;

	static const int hdrlength = 8;
	udph = (struct udphdr*) p_buf_get_data_ptr(buffer, hdrlength);
	
	
	
	udph->uh_sport = htons(udpconf->sport);
	udph->uh_dport = htons(udpconf->dport);
	udph->uh_ulen = htons((hdrlength + buffer->data_size));
	udph->uh_sum = 0;

	udph->uh_sum = htons( tcp_checksum(IPPROTO_UDP,
						   udph,
						   buffer->data_size,	
						   *udpconf->ip_dst_, 
						   *udpconf->ip_src_) );
}


