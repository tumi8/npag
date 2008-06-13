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

#include <stdio.h>
#include <string.h>
#include <stdlib.h> //atof
#include <netdb.h>
#include "memory.h"

#include "config.h"
#include "automata.h"
#include "states.h"


#include <netinet/in.h> //IPPROTO_XXX
#include <arpa/inet.h>


extern int fp_line; /* line of FILE pointer */
extern int word_line;	/* line of word that was read last */


struct addrinfo **tmpip_src;
struct addrinfo **tmpip_dst;
int *tmpipproto;


/****************************************************************************
 * First state of the automata. A new stream specification should start e.g.
 * 'stream' is the next word that is expected.
 ****************************************************************************/
void begin(char *word, config_t *conf, automata_t *automata) {
 
	if( strcmp(word, "stream") == 0 ) {
		//fprintf(stderr, "STREAM\n");
		//TODO initialize conf
		//automata->state = STREAM;
	}

	/* Error: new stream specification should begin with word 'stream' */
	else {
		fprintf(stderr, "ERROR line %i: got '%s' but 'stream' expected\n", word_line, word);
		exit(0);
	}
}
void check_begin(config_t *conf) {
	//fprintf(stderr, "check_begin..\n");
 	
 	conf->next = cmalloc(sizeof(config_t));
	conf = conf->next;
	conf->traffic.pattern = NULL;
	conf->next = NULL;
	
	conf->trans_proto_type = -1;
	conf->net_proto_type = -1;
	conf->ipproto = IPPROTO_RAW;
	
	tmpip_src = cmalloc(sizeof(struct addrinfo*));
	tmpip_dst = cmalloc(sizeof(struct addrinfo*));
	tmpipproto = cmalloc(sizeof(int));
	*tmpipproto = IPPROTO_RAW;
	
}

void init_stream(config_t *conf) {
 	/*
 	fprintf(stderr, "new config + tmpip..\n");
 	conf->next = (config_t*)cmalloc(sizeof(config_t));
	conf = conf->next;
	conf->traffic.pattern = NULL;
	conf->next = NULL;
	
	tmpip_src = (struct addrinfo**)cmalloc(sizeof(struct addrinfo*));
	tmpip_dst = (struct addrinfo**)cmalloc(sizeof(struct addrinfo*));
	tmpipproto = (int*) cmalloc(sizeof(int));*/
}
void check_stream(config_t *conf) {
	/* empty */
}
void read_stream(char *word, char *val, config_t *conf, automata_t *automata) {
		if(strcmp(word, "mode") == 0) {
			if(strcmp(val, "kernel") == 0) {
				conf->kernel_packet = TRUE;
			}
			else if(strcmp(val, "raw") == 0) {
				conf->kernel_packet = FALSE;
			}
			else {
				fprintf(stderr, "ERROR line %i: unknown parameter '%s'. Use "\
					"'kernel' or 'raw' instead!\n", fp_line, val);
				exit(0);
			}
		}
		
		 else if( strcmp(word, "}" ) == 0) {
			if(!automata->network_defined) {
				fprintf(stderr, "ERROR line %i: ip or ip6 expected\n", word_line);
				exit(0);
			}
			if(!automata->transport_defined) {
				fprintf(stderr, "WARNING line %i: no transport protocol defined\n", word_line);
			}
			if(!automata->traffic_defined) {
				fprintf(stderr, "ERROR line %i: no traffic parameters defined\n", word_line);
				exit(0);
			}
			automata->reset = TRUE;
			automata->state = BEGIN;
		}

		else {
			fprintf(stderr, "ERROR line %i: unknown protocol - %s\n", word_line, word);
			exit(0);
		}
	//}


}


/* -------------------------------------------------------------------------------------
 				IP protocol specification
----------------------------------------------------------------------------------------*/

void init_ip(config_t* conf) {
	conf->net_proto_type = TYPE_IP4;
	conf->net_proto = cmalloc(sizeof(ip4conf_t));
	ip4conf_t *ip = conf->net_proto;
	
	//TODO this only makes sence if no options can be specified!
	ip->version = 4;
	ip->hl = 5;
	ip->off = 0;
	ip->protocol = tmpipproto;
	ip->ttl = 120;
	ip->id = 0;
	ip->tos = 0;
	
	// ensure that no randomization is performed by default
	ip->dst_mask = 0xFFFFFFFF;
	ip->src_mask = 0xFFFFFFFF;

}
void check_ip(config_t* conf) {
	ip4conf_t *ip = conf->net_proto;
	
	if(ip->dst == 0) {
		fprintf(stderr, "ERROR line %i: no IP destination address defined\n", word_line);
		exit(0);
	}
	if(ip->src == 0) {
		fprintf(stderr, "ERROR line %i: no IP source address defined\n", word_line);
		exit(0);
	}
	
}
void read_ip(char *word, char *val, config_t *conf, automata_t *automata) {

	ip4conf_t *ip = conf->net_proto;

	if(strcmp(word, "src") == 0) {
		int ret;
		ip->src = inet_addr(val);

		ret = getaddrinfo(val, NULL, NULL, &(*tmpip_src));
		
		if(ret != 0) {
			perror("getaddrinfo src");
			exit(0);
		}
	}
	else if(strcmp(word, "dst") == 0) {
		int ret;
		ip->dst = inet_addr(val);

		ret = getaddrinfo(val, NULL, NULL, &(*tmpip_dst));
		if(ret != 0) {
			perror("getaddrinfo src");
			exit(0);
		}
	}
	else if (strcmp(word, "src_mask") == 0) {
		ip->src_mask = inet_addr(val);
	}
	else if (strcmp(word, "dst_mask") == 0) {
		ip->dst_mask = inet_addr(val);
	}
	else if(strcmp(word, "ttl") == 0) {
		ip->ttl = atoi(val);
	}
	else if(strcmp(word, "rf") == 0) {
		if(atoi(val) == 1) ip->RF = IP_RF;
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
	}
	else if(strcmp(word, "df") == 0) {
		if(atoi(val) == 1) ip->DF = IP_DF;
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
	}
	else if(strcmp(word, "mf") == 0) {
		if(atoi(val) == 1) ip->MF = IP_MF;;
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
	}
	else if(strcmp(word, "version") == 0) {
		ip->version = atoi(val);
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
		
	}
	else if(strcmp(word, "hlength") == 0) {
		ip->hl = atoi(val);
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
		
	}
	else if(strcmp(word, "off") == 0) {
		ip->off = atoi(val);
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
		
	}
	else if(strcmp(word, "id") == 0) {
		ip->id = atoi(val);
		if(conf->kernel_packet) 
			fprintf(stdout, "WARNING line %i: with kernel packets the IP id option is omitted\n"\
							"\t(this option is specified by the kernel\n", word_line);			
	}


	else if(strcmp(word, "tos") == 0) {
		ip->tos = atoi(val);
	}

	else if(strcmp(word, "}") == 0) {
		//check_ip(conf);
		automata->network_defined = TRUE;
		automata->state = STREAM;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown IP parameter - %s\n", word_line, word);
		exit(0);
	}
}

/* -------------------------------------------------------------------------------------
 				IP version 6 protocol specification
----------------------------------------------------------------------------------------*/

void init_ip6(config_t* conf) {
	conf->net_proto_type = TYPE_IP6;
	conf->net_proto = cmalloc(sizeof(ip6conf_t));
	ip6conf_t* ip6 = conf->net_proto;
	ip6->traffic_class = 0;
	ip6->flowlabel = 0;
	ip6->nexthdr = *tmpipproto;
	ip6->hoplimit = 64;
}
void check_ip6(config_t* conf) {
	ip6conf_t* ip6 = conf->net_proto;
	
	if(strcmp(ip6->dst,"") == 0) {
		fprintf(stderr, "ERROR line %i: no IP6 destination address defined\n", word_line);
		exit(0);
	}
}
void read_ip6(char *word, char *val, config_t *conf, automata_t *automata) {
	
	ip6conf_t *ip6 = conf->net_proto;

	if(strcmp(word, "src") == 0) {
		int ret;
		strcpy(ip6->src, val);

		ret = getaddrinfo(val, NULL, NULL, &(*tmpip_src));
		
		if(ret != 0) {
			perror("getaddrinfo src");
			exit(0);
		}
	}
	else if(strcmp(word, "dst") == 0) {
		int ret;
		strcpy(ip6->dst, val);

		ret = getaddrinfo(val, NULL, NULL, &(*tmpip_dst));
		if(ret != 0) {
			perror("getaddrinfo src");
			exit(0);
		}
	}
	else if(strcmp(word, "hoplimit") == 0) {
		ip6->hoplimit = atoi(val);
	}
	else if(strcmp(word, "flowlabel") == 0) {
		ip6->flowlabel = atoi(val);
	}
	else if(strcmp(word, "tc") == 0) {
		ip6->traffic_class = atoi(val);
	}
	else if(strcmp(word, "interface") == 0) {
		strcpy(ip6->interface, val);;
	}
	
	else if(strcmp(word, "}") == 0) {
		//check_ip6(conf);
		automata->network_defined = TRUE;
		automata->state = STREAM;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown IPv6 parameter - %s\n", word_line, word);
		exit(0);
	}
}


/* -------------------------------------------------------------------------------------
 				ICMP protocol specification
----------------------------------------------------------------------------------------*/

void init_icmp(config_t* conf) {
	conf->trans_proto_type = TYPE_ICMP;
	conf->ipproto = IPPROTO_ICMP; //TODO conf->trans_proto_type is actually the same...
	conf->trans_proto = cmalloc(sizeof(icmpconf_t));
	icmpconf_t *icmp = conf->trans_proto;
	icmp->type = 3;
	icmp->code = 0;
	
	icmp->id = 0;
	icmp->seq = 0;
	icmp->pptr = 0;
	*tmpipproto = IPPROTO_ICMP;
}
void check_icmp(config_t* conf) {
}
void read_icmp(char *word, char *val, config_t *conf, automata_t *automata) {
	icmpconf_t *icmp = conf->trans_proto;
	
	if(strcmp(word, "type") == 0) {
		icmp->type = atoi(val);
	}
	else if(strcmp(word, "code") == 0) {
		icmp->code = atoi(val);
	}
	else if(strcmp(word, "id") == 0) {
		icmp->id = atoi(val);
	}
	else if(strcmp(word, "seq") == 0) {
		icmp->seq = atoi(val);
	}
	else if(strcmp(word, "pointer") == 0) {
		icmp->pptr = (unsigned char)atoi(val);
	}
	else if(strcmp(word, "gw_addr") == 0) {
		strncpy(icmp->gw_addr, val, 16);
	}
	else if(strcmp(word, "}") == 0) {
		automata->transport_defined = TRUE;
		automata->state = STREAM;
	}
	else {
		fprintf(stderr, "ERROR line %i: unknown icmp parameter - %s\n", word_line, word);
		exit(0);
	}
	
}


/* -------------------------------------------------------------------------------------
 				ICMP VERSION 6 protocol specification
----------------------------------------------------------------------------------------*/
void init_icmp6(config_t *conf) {
	conf->trans_proto_type = TYPE_ICMP6;
	conf->trans_proto = cmalloc(sizeof(icmp6conf_t));
	icmp6conf_t* icmp6 = conf->trans_proto;
	conf->ipproto = IPPROTO_ICMPV6;
	icmp6->id = 0;
	icmp6->seq = 0;
	icmp6->pointer = 0;
	icmp6->mtu = 0;
	icmp6->code = 0;
	
}
void check_icmp6(config_t *conf) {
}
void read_icmp6(char *word, char *val, config_t *conf, automata_t *automata) {
	icmp6conf_t *icmp6 = conf->trans_proto;
	
	if(strcmp(word, "type") == 0) {
		icmp6->type = atoi(val);
	}
	else if(strcmp(word, "code") == 0) {
		icmp6->code = atoi(val);
	}
	else if(strcmp(word, "mtu") == 0) {
		icmp6->mtu = atoi(val);
	}
	else if(strcmp(word, "pointer") == 0) {
		icmp6->pointer = atoi(val);
	}
	else if(strcmp(word, "id") == 0) {
		icmp6->id = atoi(val);
	}
	else if(strcmp(word, "seq") == 0) {
		icmp6->seq = atoi(val);
	}
	else if(strcmp(word, "mrd") == 0) {
		icmp6->mrd = atoi(val);
	}
	else if(strcmp(word, "}") == 0) {
		automata->transport_defined = TRUE;
		automata->state = STREAM;
	}
	else {
		fprintf(stderr, "ERROR line %i: unknown icmp6 parameter - %s\n", word_line, word);
		exit(0);
	}
}




/* -------------------------------------------------------------------------------------
 				TCP protocol specification
----------------------------------------------------------------------------------------*/

void init_tcp(config_t* conf) {
	
	conf->trans_proto_type = TYPE_TCP;
	conf->ipproto = IPPROTO_TCP; //TODO conf->trans_proto_type is actually the same...
	conf->trans_proto = cmalloc(sizeof(tcpconf_t));
	tcpconf_t* tcp = conf->trans_proto;
	tcp->mss = 1500;
	tcp->seq = 0;
	tcp->win = 512;
	tcp->urp = 0;
	tcp->off = 5; //TODO this only makes sence if no options can be specified!
    tcp->sport = 0;
    tcp->sport_low = 0;
    tcp->sport_high = 0;
    tcp->dport = 0;
    tcp->dport_low = 0;
    tcp->dport_high = 0;
	tcp->nodelay = FALSE;
	*tmpipproto = IPPROTO_TCP;
}
void check_tcp(config_t* conf) {
	//fprintf(stderr, "tcp_check\n");
	tcpconf_t* tcp = conf->trans_proto;
	
		tcp->ip_src_ = tmpip_src;
		tcp->ip_dst_ = tmpip_dst;
		
		
		
	if(tcp->dport == 0) {
		fprintf(stderr, "ERROR line %i: no TCP destination port defined\n", word_line);
		exit(0);
	}
}

void read_tcp(char *word, char *val, config_t *conf, automata_t *automata) {

	tcpconf_t *tcp = conf->trans_proto;


	 if(strcmp(word, "mss") == 0) {
		tcp->mss = atoi(val);
	}
	else if(strcmp(word, "payloadsize") == 0) {
		tcp->payload_size = atoi(val);
	}
	else if(strcmp(word, "win") == 0) {
		tcp->win = atoi(val);
	}
	else if(strcmp(word, "sport") == 0) {
		tcp->sport = atoi(val);
	}
	else if(strcmp(word, "sport_low") == 0) {
		tcp->sport_low = atoi(val);
        if (!tcp->sport_high) tcp->sport_high = tcp->sport_low;
	}
	else if(strcmp(word, "sport_high") == 0) {
		tcp->sport_high = atoi(val);
        if (!tcp->sport_low) tcp->sport_low = tcp->sport_high;
	}
	else if(strcmp(word, "dport") == 0) {
		tcp->dport = atoi(val);
	}
	else if(strcmp(word, "dport_low") == 0) {
		tcp->dport_low = atoi(val);
        if (!tcp->dport_high) tcp->dport_high = tcp->dport_low;
	}
	else if(strcmp(word, "dport_high") == 0) {
		tcp->dport_high = atoi(val);
        if (!tcp->dport_low) tcp->dport_low = tcp->dport_high;
	}

	else if(strcmp(word, "seq") == 0) {
		tcp->seq = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the sequence number option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "ack") == 0) {
		tcp->ACK = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the ACK flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "acknum") == 0) {
		tcp->ack = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the ACK number option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "syn") == 0) {
		tcp->SYN = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the SYN flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "push") == 0) {
		tcp->PUSH = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the PUSH flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "fin") == 0) {
		tcp->FIN = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the FIN flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "urg") == 0) {
		tcp->URG = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the URG flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "rst") == 0) {
		tcp->RST = atoi(val);
		if(conf->kernel_packet)
			fprintf(stdout, "WARNING line %i: with kernel packets the RST flag option is omitted\n"\
						"\t(this option is specified by the kernel)\n", word_line);
	}
	else if(strcmp(word, "nodelay") == 0) {
		tcp->nodelay = atoi(val);
	}


	else if(strcmp(word, "}") == 0) {
		//check_tcp(conf);
	
		
		automata->transport_defined = TRUE;
		automata->state = STREAM;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown parameter - %s\n", word_line, word);
		exit(0);
	}

    if (tcp->sport_low > 0 && tcp->sport_high > 0 && tcp->sport_high < tcp->sport_low) {
        fprintf(stdout, "ERROR: sport_low is higher than sport_high\n");
        exit(2);
    }
    if (tcp->dport_low > 0 && tcp->dport_high > 0 && tcp->dport_high < tcp->dport_low) {
        fprintf(stdout, "ERROR: dport_low is higher than dport_high\n");
        exit(2);
    }
	
}

/* -------------------------------------------------------------------------------------
 				UDP protocol specification
----------------------------------------------------------------------------------------*/

void init_udp(config_t* conf) {
	conf->trans_proto_type = TYPE_UDP;
	conf->ipproto = IPPROTO_UDP; //TODO conf->trans_proto_type is actually the same...
	conf->trans_proto = cmalloc(sizeof(udpconf_t));
	udpconf_t* udp = conf->trans_proto;
	udp->sport = 5000;
	udp->len = 3;
	*tmpipproto = IPPROTO_UDP;
}
void check_udp(config_t* conf) {
	udpconf_t* udp = conf->trans_proto;
	
	//fprintf(stderr, "udp  check call\n");
	
	udp->ip_src_ = tmpip_src;
	udp->ip_dst_ = tmpip_dst;
		
	if(udp->dport == 0) {
		fprintf(stderr, "ERROR line %i: no UDP destination port defined\n", word_line);
		exit(0);
	}
}
void read_udp(char *word, char *val, config_t *conf, automata_t *automata) {
	udpconf_t *udp = conf->trans_proto;
	
	if(strcmp(word, "packet") == 0) {
		if(strcmp(val, "kernel") == 0) {
			conf->kernel_packet = TRUE;
		}
		else if(strcmp(val, "raw") == 0) {
			conf->kernel_packet = FALSE;
		}
		else {
			fprintf(stderr, "ERROR line %i: unknown parameter '%s'. Use "\
					"'kernel' or 'raw' instead!\n", fp_line, val);
			exit(0);
		}
	}
	
	else if(strcmp(word, "sport") == 0) {
		udp->sport = atoi(val);
	}

	else if(strcmp(word, "dport") == 0) {
		udp->dport = atoi(val);
	}
	
	else if(strcmp(word, "payloadsize") == 0) {
		udp->payload_size = atoi(val);
	}
	else if(strcmp(word, "payloadfile") == 0) {
		strncpy(udp->pfile, val, 20);
	}
	
	else if(strcmp(word, "}") == 0) {
		//check_udp(conf);

		automata->transport_defined = TRUE;
		automata->state = STREAM;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown parameter - %s\n", word_line, word);
		exit(0);
	}
}

/* -------------------------------------------------------------------------------------
 				Traffic specification
----------------------------------------------------------------------------------------*/
void init_traffic(config_t *conf) {
	/* empty */
}
void check_traffic(config_t *conf) {
	/* empty */
}
void read_traffic(char *word, char *val, config_t *conf, automata_t *automata) {

	if(strcmp(word, "repeat") == 0) {	
		conf->traffic.repeat = atoi(val);
	}
	
	else if(strcmp(word, "}") == 0) {
		automata->traffic_defined = TRUE;
		automata->state = STREAM;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown traffic parameter - %s\n", word_line, word);
		exit(0);
	}

}

void init_pattern(config_t *conf) {
		
		if(conf->traffic.pattern == NULL) {
			conf->traffic.pattern = cmalloc(sizeof(pattern_t));
			conf->traffic.pattern->next = NULL;
		}
		else {
			pattern_t *pattern = conf->traffic.pattern; 
			/*  goto last element of linked list */
			while(pattern->next != NULL)
				pattern = pattern->next;

			pattern->next = cmalloc(sizeof(pattern_t));
			pattern = pattern->next;
			pattern->next = NULL;
		}	
}

void check_pattern(config_t *conf) {
	/* empty */
}
void read_pattern(char *word, char *val, config_t *conf, automata_t *automata) {
	pattern_t *pattern = conf->traffic.pattern;

	/* goto last element of linked list */
	while(pattern->next != NULL)
		pattern = pattern->next;

	if(strcmp(word, "send_packets") == 0) {
		pattern->send_packets = atoi(val);
	}
	else if(strcmp(word, "delay") == 0) {
		pattern->delay = atof(val);
	}
	else if(strcmp(word, "repeat") == 0) {
		pattern->repeat = atoi(val);
	}
	else if(strcmp(word, "size") == 0) {
		pattern->payload_size = atof(val);
	}
	else if(strcmp(word, "filename") == 0) {
		if(strncmp( val + (strlen(val) - 3), "hex", 3) == 0) {
			pattern->file_format = HEX;
			strncpy(pattern->payload_file, val, 20);	
			/* fprintf(stderr, "HEX\n");*/
		}
		else if(strncmp( val + (strlen(val) - 4), "byte", 4) == 0) {
			pattern->file_format = BYTE;
			strncpy(pattern->payload_file, val, 20);
			/* fprintf(stderr, "BYTE\n"); */
		}
		else {
			fprintf(stderr, "ERROR line %i: %s file extension should be .hex or .byte\n", word_line, val);
			exit(0);	
		}
	
	// fprintf(stderr, "%i = length of filename\n", strlen(val));
	//	strncpy(pattern->payload_file, val, 20);
	//	pattern->file_format = BYTE;	
	}
	/*
	else if(strcmp(word, "file_byte") == 0) {
		strncpy(pattern->payload_file, val, 20);
		pattern->file_format = BYTE;	
	}
	else if(strcmp(word, "file_hex") == 0) {
		strncpy(pattern->payload_file, val, 20);
		pattern->file_format = HEX;	
	}*/
	
	else if(strcmp(word, "}") == 0) {
		automata->state = TRAFFIC;
	}

	else {
		fprintf(stderr, "ERROR line %i: unknown pattern parameter - %s\n", word_line, word);
		exit(0);
	}

}
