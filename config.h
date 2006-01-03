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

typedef int BOOL;
#define TRUE 1
#define FALSE 0

/*
enum type {	TYPE_TCP = 1,
 		TYPE_UDP,
		TYPE_ICMP,
		TYPE_ICMP6,
		TYPE_IP4,
		TYPE_IP6 };

typedef enum type e_type;
*/
enum trans_type {
	TYPE_TCP = 1,
 	TYPE_UDP,
    TYPE_ICMP6,
    TYPE_ICMP
}; //trans_type_t;
typedef enum trans_type trans_type_t;

enum net_type {
	TYPE_IP4 = 1,
 	TYPE_IP6
}; //net_type_t;
typedef enum net_type net_type_t;



#define MAXFILENAME 255

enum e_format {HEX = 1, BYTE };
//#include "npag.h"



typedef struct pattern {
	int send_packets;	/* number of packets that should be sent */
	double delay;		
	int repeat;
	int payload_size;
	
	char payload_file[MAXFILENAME];
	int file_format;	/* the file can be HEX or BYTE */
	
	struct pattern *next; /* specifies the filename the payload 
 							 should be read from */
}pattern_t;


typedef struct traffic {
	int repeat;
	struct pattern *pattern;	
}traffic_t;


typedef struct ip6conf {

	int traffic_class;
	int flowlabel;
	int nexthdr;
	int hoplimit;
	char interface[5]; /* outgoing interface, e.g. "eth0" */

	/* source and destination address */
	char src[16];      
	char dst[16];      
}ip6conf_t;


typedef struct ip4conf {

    int version;
	int hl; /* 4 bytes */
	int tos;			
	int id;
	
	/* fragment flags */
	BOOL RF;
	BOOL DF;
	BOOL MF;			
	int off;			
	int ttl;			
	int *protocol;		/* upper layer protocol */
	
	/* source and destination address */
	char src[16];
	char dst[16];

	int *trans_proto_num;
}ip4conf_t;


typedef struct tcpconf {

	int mss;		
	BOOL nodelay;	/* enable or disable nagel?s algorithm */

	int sport;		
	int dport;		
	int seq;		
	int ack;		
	int win;		
	int urp;		
	int off;		/* tcp offset. This should be set to 4 since 
					   options are not supported yet */

	/* TCP Flags */
	BOOL FIN;	
 	BOOL SYN;
 	BOOL RST;
 	BOOL PUSH;
 	BOOL ACK;
 	BOOL URG;
 	
 	int payload_size;
 	char pfile[MAXFILENAME]; /* specifies the filename the payload 
 								should be read from */
 	
 	/* we need this for checksum calculation */
	struct addrinfo **ip_src_;
	struct addrinfo **ip_dst_;
	
}tcpconf_t;

typedef struct udpconf {
	int sport;
	int dport;
	int len;
	int payload_size;
	char pfile[MAXFILENAME];
	
	/* we need this for checksum calculation */
	struct addrinfo **ip_src_;
	struct addrinfo **ip_dst_;
}udpconf_t;


typedef struct icmpconf {
	int type;
	int code;
	
	char gw_addr[16];
	short id;
	short seq;
	unsigned char pptr;
}icmpconf_t;


typedef struct icmp6conf {
	unsigned char type;
	unsigned char code;
	
	unsigned int mtu;
	unsigned int pointer;
	
	unsigned short id;
	unsigned short seq;
	
	unsigned short mrd;
}icmp6conf_t;


/* This structure contains the infomation about the protocols that
 * should be send over the net and the traffic parameters */
typedef struct config {

	//e_type transport;
	//e_type network;
	trans_type_t trans_proto_type;
	net_type_t net_proto_type;
	
	int ipproto;
	
	/* specifies if the kernel?s protocol implementation is
	   used or if we have an own implementation, i.e. 
	   raw sockets are used */
	BOOL kernel_packet;

	/* pointer to configuration structure for network protocol header, 
	   e.g. ipconf_t, ip6conf_t etc ... */
	void *net_proto;
	
	/* pointer to configuration structure for transport protocol header, 
	   e.g. tcpconf_t, udpconf_t etc ... */
	void *trans_proto;

	/* traffic parameters */
	traffic_t traffic;
	
	/* next configuration structure */
	struct config *next;
} config_t;



