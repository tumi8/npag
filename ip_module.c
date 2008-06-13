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
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/in.h> //IPPROTO
#include <arpa/inet.h> //inet_pton
#include <string.h> //memset
#include <net/if.h> //map interface to index
#include "sendinfo.h"
#include "packet_buffer.h"
#include "config.h"

#define SIN6_LEN //required for compile-time tests

void 	__P(check(char *msg, int c));
int checksum 	__P((u_int16_t *buf, int nbytes));
u_int16_t 	__P(tcp_checksum());
void 			__P(set_payload());
void 			__P(check_warning());
typedef int sock_descriptor_t;




void set_ipsockopts(packet_buffer_t* sendinfo, config_t *conf){
	ip4conf_t* ipconf = conf->net_proto;
	int ret; 
	
	ret = setsockopt(*sendinfo->fd, IPPROTO_IP, IP_TOS, &ipconf->tos, sizeof(int));
	check_warning("WARNING IP tos option", ret);
	ret = setsockopt(*sendinfo->fd, IPPROTO_IP, IP_TTL, &ipconf->ttl,sizeof(int));
	check_warning("WARNING IP ttl option", ret);
}



/* Interface for init_socket */
void init_rawsocket(sock_descriptor_t *fd, config_t *conf) {
	int ret;
	int one = 1;
	struct sockaddr_in dst_addr;
	ip4conf_t *ipconf;
	
	ipconf = (ip4conf_t*)conf->net_proto;	
	
	*fd = socket(PF_INET, SOCK_RAW, conf->ipproto);
	check("raw socket", *fd);

	ret = setsockopt(*fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	check("setsockopt (IP_HDRINCL)", ret);
	
	
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = 0;
	struct in_addr in = { ipconf->dst };
	dst_addr.sin_addr = in;
	memset(&dst_addr.sin_zero, '0', 8);
		
	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));
	check("raw socket (connect)", ret);
	
}



/* Interface for set_nethdr */
void fill_ip4hdr(packet_buffer_t *sendinfo, config_t *conf) {
	ip4conf_t *ipconf = conf->net_proto;
	
	packet_buffer_t *buffer = sendinfo;
	struct ip *iph;
	/*NOTE:  no options defined, that is header length is 5 * 4 bytes.
	 * The value in ipconf->hl (which defines the header length) can now have
	 * a wrong value..this can be usefull to check the behaviour of a firewall...
	 * If header length is dynamic you should comment the next line
	 * and uncomment the line that follows the next line */
	 iph = (struct ip*) p_buf_get_data_ptr(buffer, 5 * 4); 
	 /* iph = (struct ip*) p_buf_get_data_ptr(buffer, ipconf->hl * 4); */
	

	iph->ip_hl = ipconf->hl;
	iph->ip_v = ipconf->version;
	iph->ip_len = htons(buffer->data_size);

	iph->ip_tos = ipconf->tos;

	iph->ip_id = htons(ipconf->id);
	//iph->ip_off = htons(ipconf->off);
	iph->ip_off = htons( ipconf->DF | ipconf->MF | ipconf->RF | ipconf->off);
	iph->ip_ttl = ipconf->ttl;
	iph->ip_p = *ipconf->protocol;
	iph->ip_sum = 0;

	struct in_addr sin = { ipconf->src };
	struct in_addr din = { ipconf->dst };
	iph->ip_src = sin;
	iph->ip_dst = din;
	
	iph->ip_sum =  checksum((u_int16_t*)iph, 20);	
}




 
void init_rawsocket6(sock_descriptor_t *fd, config_t *conf) {
	int ret;
	struct sockaddr_in6 dst_addr;
	ip6conf_t *ipconf;
	
	unsigned int tc = 10;
	
	ipconf = (ip6conf_t*)conf->net_proto;	
	
	*fd = socket(PF_INET6, SOCK_RAW, conf->ipproto);
	check("raw socket", *fd);

	/* Note: there is nothing like HDRINCL in IPv6. Ancillary data
	   must be used to set the header values of IP packets */
		
	dst_addr.sin6_family = AF_INET6;
	dst_addr.sin6_port = 0;
	inet_pton(AF_INET6, ipconf->dst, &dst_addr.sin6_addr);
	dst_addr.sin6_flowinfo = htonl(tc << 4 | 2);
    dst_addr.sin6_scope_id = if_nametoindex(ipconf->interface);
 	
	ret = connect(*fd, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
	check("raw socket (connect)", ret);

}


void fill_ip6hdr(packet_buffer_t *sendinfo, config_t *conf) {
	ip6conf_t *ipconf = conf->net_proto;
	struct cmsghdr *cmsg;
	//struct in6_pktinfo pktinfo;
	char buf[CMSG_SPACE(sizeof(char)) * 1000];
	
	//struct in6_pktinfo *fdptr;
	int *intptr;
	
	//char *testIP = "fe80::30:8475:c8c0";
	
	//sendinfo->msg;
	//inet_pton(AF_INET6, testIP, &pktinfo.ipi6_addr);
	//pktinfo.ipi6_ifindex = if_nametoindex("eth0");	
	
	sendinfo->msg.msg_control = buf;
    sendinfo->msg.msg_controllen = sizeof buf;
    
    /*
    cmsg = CMSG_FIRSTHDR(&sendinfo->msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo));
	
	fdptr = (struct in6_pktinfo*)CMSG_DATA(cmsg);
	*fdptr = pktinfo;
	*/
	
//	sendinfo->msg.msg_controllen = cmsg->cmsg_len;
	
	//cmsg = CMSG_NXTHDR( &sendinfo->msg, cmsg );
	cmsg = CMSG_FIRSTHDR( &sendinfo->msg );
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPLIMIT;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	intptr = (int*) CMSG_DATA(cmsg);
	*intptr = ipconf->hoplimit;
	
	sendinfo->msg.msg_controllen = cmsg->cmsg_len;
	
	cmsg = CMSG_NXTHDR( &sendinfo->msg, cmsg );
	
	// Build the packet..
	
	packet_buffer_t *buffer = (sendinfo);
	struct ip6_hdr *ip6h;

	
	ip6h = (struct ip6_hdr*) p_buf_get_data_ptr(buffer, 40);
	ip6h->ip6_hops = ipconf->hoplimit;
	ip6h->ip6_vfc = 6 << 4;
	ip6h->ip6_nxt = conf->ipproto;
	ip6h->ip6_plen = htons(buffer->data_size - 40);
	
	inet_pton(AF_INET6, ipconf->src, &ip6h->ip6_src);
	inet_pton(AF_INET6, ipconf->dst, &ip6h->ip6_dst);
	
	buffer->data_size -= 40;
	buffer->data_ptr += 40;
}


