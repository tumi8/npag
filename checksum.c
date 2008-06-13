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
#include <stdlib.h> //malloc
#include <string.h> //memset

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <netdb.h> //getaddrinfo

#include "sendinfo.h"
#include "memory.h"


struct pseudo4_hdr {
	struct in_addr source;
	struct in_addr dest;
	u_int8_t place_holder;
	u_int8_t protocol;
	u_int16_t length;
} ;

struct pseudo6_hdr {
	struct in6_addr source;
	struct in6_addr dest;
	u_int8_t place_holder;
	u_int8_t protocol;
	u_int16_t length;
} ;




int checksum (u_int16_t *buf, int nbytes) {

	u_int32_t sum;
	u_int16_t oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_int16_t *) &oddbyte) = *(u_int8_t *) buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (u_int16_t) ~sum;
}



u_int16_t tcp_checksum(u_int8_t proto,char *packet,int len, struct addrinfo *ai_dst,struct addrinfo *ai_src ) {
	char *pseudo_pkt;
	u_int16_t answer;

	struct pseudo4_hdr pseudo4;
	struct pseudo6_hdr pseudo6;

	struct sockaddr_in *src4;
	struct sockaddr_in *dst4;
	struct sockaddr_in6 *src6;
	struct sockaddr_in6 *dst6;


	if(ai_dst->ai_family == AF_INET6) {
		src6 = (struct sockaddr_in6*)ai_src->ai_addr;
		dst6 = (struct sockaddr_in6*)ai_dst->ai_addr;
		pseudo6.protocol = proto;
		pseudo6.length = htons(len);
		pseudo6.place_holder = 0;

		pseudo6.source = src6->sin6_addr;
		pseudo6.dest = dst6->sin6_addr;

		pseudo_pkt = cmalloc( sizeof(pseudo6)+len );

		memcpy(pseudo_pkt,&pseudo6,sizeof(pseudo6));
		memcpy((pseudo_pkt+sizeof(pseudo6)),packet,len);

		answer=(u_int16_t)checksum((u_int16_t *)pseudo_pkt,(len+sizeof(pseudo6)));
		free(pseudo_pkt);
		return answer;
	}

	if(ai_dst->ai_family == AF_INET) {
		src4 = (struct sockaddr_in*)ai_src->ai_addr;
		dst4 = (struct sockaddr_in*)ai_dst->ai_addr;
		pseudo4.protocol = proto;
		pseudo4.length = htons(len);
		pseudo4.place_holder = 0;

		pseudo4.source = src4->sin_addr;
		pseudo4.dest = dst4->sin_addr;



		pseudo_pkt = cmalloc(sizeof(pseudo4)+len);
		

		memcpy(pseudo_pkt,&pseudo4,sizeof(pseudo4));
		memcpy((pseudo_pkt+sizeof(pseudo4)),packet,len);

		answer=(u_int16_t)checksum((u_int16_t *)pseudo_pkt,(len+sizeof(pseudo4)));
		free(pseudo_pkt);
		return answer;
	}


	/* NOT REACHED */
	fprintf(stderr, "Internal Error: this code should not be reached! (tcp_checksum)\n");
	return -1; 
}








