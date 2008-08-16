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

void init_tcpsocket		__P((sock_descriptor_t *fd, config_t*));
void init_tcpip6socket	__P((sock_descriptor_t *fd, config_t*));
void set_tcpsockopts	__P((packet_buffer_t*, config_t*));
void fill_tcphdr		__P((packet_buffer_t*, config_t*));
void rand_tcp(packet_buffer_t *sendinfo, config_t *conf);
void rand_tcp_fast(config_t *conf, packet_buffer_t *sendinfo);
void src_ip_inc();
void dst_ip_inc();
void src_port_inc();
void dst_port_inc();
