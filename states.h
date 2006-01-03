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

#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */

void begin			__P((char *word, config_t *conf, automata_t *automata));
void check_begin			__P(( config_t *conf));


void read_stream	__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_stream	__P((config_t*));
void check_stream	__P((config_t*));

void read_ip		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_ip		__P((config_t*));
void check_ip		__P((config_t*));

void read_ip6		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_ip6		__P((config_t*));
void check_ip6		__P((config_t*));

void read_tcp		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_tcp		__P((config_t*));
void check_tcp		__P((config_t*));

void read_udp		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_udp		__P((config_t*));
void check_udp		__P((config_t*));

void read_icmp		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_icmp		__P((config_t*));
void check_icmp		__P((config_t*));

void read_icmp6		__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_icmp6		__P((config_t*));
void check_icmp6	__P((config_t*));

void read_traffic	__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_traffic	__P(());
void check_traffic	__P((config_t*));

void read_pattern	__P((char *word, char *val, config_t *conf, automata_t *automata));
void init_pattern	__P((config_t*));
void check_pattern	__P((config_t*));

