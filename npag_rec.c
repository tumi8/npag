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

#include	<stdio.h>	/* for fputs()	*/
//#include	<errno.h>	/* for perror()	*/
#include	<netdb.h>	/* for addrinfo	*/
#include	<sys/types.h>	/* for socket()	and connect() 	*/
#include	<sys/socket.h>
#include	<unistd.h>	/* for read() and close()	*/

#include <string.h>
#include <stdlib.h> //malloc, free, atoi, exit...
#include <sys/time.h> //gettimeofday

//#define 	MAXLINE	4096
#define		LISTENQ 1024


//#define MAXDATA	65536

#define TRUE 1
#define FALSE 0
#define MAXFILENAME 20

typedef int BOOL;





struct s_adhdr {
	int payload_size;
	struct timeval tv;
	int seq;

	unsigned short mysize;
};

struct s_time_record {
	struct timeval my_time;
	struct timeval his_time;
	int seq;

	struct s_time_record *next;
}time_record_head, *time_record_tail;


struct s_seqlist {
	int val;
	struct s_seqlist *next;
}seqlist_head, *seqlist_tail;


static void usage() {
	printf("\nUsage: npag_rec [interface address] [-options]\n"\
	       "       npag_rec host [-options]\n\n" \
	       "interface address: address to bind\n" \
	       "Options:\n" \
	       "\t -u    receive UDP packets\n" \
	       "\t -t    receive TCP packets\n"
	       "\t -p##  portnumber to listen at\n\n");
	exit(0);
}



void insert_seq(int val);
void delete_seq(int val);
void insert_time_record(struct timeval my_time, struct timeval his_time, int seq);
void free_seqlist(struct s_seqlist*);
void free_time_record(struct s_time_record*);


void read_tcp(int fd);
void read_udp(int fd);
void print_statistics(int socktype, struct timeval start, struct timeval end, int total_bytes, int io);

struct addrinfo *getaddrlist(const char *host, const char *port, int flags, int family, int socktype);
int init_sock(struct addrinfo *ai);
void check(char *msg, int num);

/* timer functions */
void tvsub(struct timeval*, struct timeval*, struct timeval*);
void tvadd(struct timeval*, struct timeval*, struct timeval*);
double tvtosec(struct timeval *tv);




/* FILE *output;
int verbose;
BOOL out;
*/
int buflen = 4 * 1024;

int main(int argc, char **argv) {

	int 	fd;
	//time_t	ticks;
	//char	buff[MAXLINE];
	struct addrinfo	*ai;
	int socktype;
	char port[5];
	/*char *filename;
	out = FALSE;
	verbose = 0; */

	char *server_name = argv[1];


	time_record_tail = &time_record_head; /* tail points to the first element,
						 i.e. the head of the list */
	seqlist_tail = &seqlist_head;
	seqlist_tail->next = NULL;

	/* default values for port and socktype */
	strncpy(port, "5001", 4);
	socktype = SOCK_STREAM;

	if (argc < 2) {
		usage();
	}



	argc--; argv++; /* skip program name */
	argc--; argv++; /* skip source address or name */

	while( argc > 0 && argv[0][0] == '-' )  {
		switch (argv[0][1]) {
			case 'u': socktype = SOCK_DGRAM;
				break;
			case 't': socktype = SOCK_STREAM;
				break;
			case 'p': strncpy(port, &argv[0][2], 5);
				break;
			case 'l': //strncpy(port, &argv[0][2], 5);
				buflen = atoi(&argv[0][2]);
				break;
			/*
			case 'v': verbose++;
				break;
			case 'o': // next string specifies a filename
				strncpy(filename,&argv[1][0] , MAXFILENAME);
				argv++; argc--; // skip filename
				out = TRUE;
				break;*/
			default:
				usage();
		};
		argv++; argc--;
	}

	/* open output file if specified */
	/*
	if(out) {
		output = fopen(filename, "w");
		if(!output) {
			fprintf(stderr, "Failed opening file for output %s: ", filename);
			perror("");
		}

	}*/

	ai = getaddrlist(server_name, port, AI_PASSIVE, AF_UNSPEC, socktype);


	fd = init_sock(ai);
	check("init_socket", fd);


	if(socktype == SOCK_STREAM) {
		printf("Waiting for TCP connection on port %s\n", port);
		read_tcp(fd);
	}
	else if(socktype == SOCK_DGRAM) {
		printf("Waiting for UDP connection on port %s\n", port);
		read_udp(fd);
	}



	/*
	if(output) {
		if(fclose(output)) {
			fprintf(stderr, "Failed closing file %s\n", filename);
			perror("");
		}
	}*/

	if(time_record_head.next != NULL)
		free_time_record(time_record_head.next);
	if(seqlist_head.next != NULL)
		free_seqlist(seqlist_head.next);

	return 0;
}

void read_tcp(int fd) {

	int fd_accept;
	int nbytes;
	//char buf[MAXDATA];
	char *buf;

	buf = (char*) malloc(sizeof(char) * buflen);
	if(buf == NULL) {
		fprintf(stderr, "Not enough memory\n");
		exit(0);
	}

	struct timeval  my_time, start, end;
	struct s_adhdr ah;
	ah.mysize = 2 * sizeof(int) + sizeof(struct timeval);

	int io = 0;
	int total_bytes = 0;


	fd_accept = accept(fd, (struct sockaddr*) NULL, NULL);
	check("accept", fd_accept);

	fprintf(stdout, "Got connection.\nStarting measurement...");
	fflush(stdout);
	gettimeofday(&start, NULL);

	while(1) {
		//nbytes = read(fd_accept, buf, sizeof(buf));
		nbytes = read(fd_accept, buf, buflen);
		gettimeofday(&my_time, NULL);
		check("recvfrom", nbytes);

		if(nbytes == 0) {
			gettimeofday(&end, NULL);
			printf("Finished.\nConnection closed by foreign host.\n");
			break;
		}
		buf[nbytes] = '\0';
		memcpy(&ah, buf, ah.mysize);

		/* it can happen that more than one packet was read */
		char *mbuf = buf;
		while(ah.payload_size < nbytes) {
			insert_time_record(my_time, ah.tv, -1); /* no sequence number, i.e. insert -1 */
			total_bytes += ah.payload_size;
			nbytes -= ah.payload_size;
			//memcpy(&ah, buf + ah.payload_size, ah.mysize);
			mbuf += ah.payload_size;
			memcpy(&ah, mbuf, ah.mysize);
		}
		if(ah.payload_size != nbytes) {
		/* we have to read payloadsize - nbytes */
			int rest = 0;
			while(nbytes != ah.payload_size) { 
				rest = read(fd_accept, buf, (ah.payload_size - nbytes));
				total_bytes += rest;
				nbytes += rest;
			}

			/*
			if(rest != (ah.payload_size - nbytes)) {
				fprintf(stderr, "INTERNAL ERROR, rest = %i, ah = %i, nbytes = %i\n",
					rest, ah.payload_size, nbytes);
				exit(0);
			}*/
		}

		insert_time_record(my_time, ah.tv, -1); /* no sequence number, i.e. insert -1 */

		io++;
		total_bytes += nbytes;
	}

	free(buf);
	print_statistics(SOCK_STREAM, start, end, total_bytes, io);
}

void read_udp(int fd) {

	int nbytes;
	//char buf[MAXDATA];
	int io = 0, total_bytes = 0;
	char *buf;

	buf = (char*) malloc(sizeof(char) * buflen);
	if(buf == NULL) {
		fprintf(stderr, "Not enough memory\n");
		exit(0);
	}

	struct timeval  my_time, start_time, end_time;

	struct s_adhdr ah;
	ah.mysize = 2 * sizeof(int) + sizeof(struct timeval);

	while(1) {
		//nbytes = read(fd, buf, sizeof(buf));
		nbytes = read(fd, buf, buflen);
		gettimeofday(&my_time, NULL);
		check("recvfrom", nbytes);
		buf[nbytes] = '\0';
		memcpy(&ah, buf, ah.mysize);

		if(ah.seq == 1) { printf("Finished.\n"); break; }

		if(ah.seq == 0) {
			fprintf(stdout, "Got Connection.\nStarting measurement...");
			fflush(stdout);
			gettimeofday(&start_time, NULL);
			continue;
		}
		insert_time_record(my_time, ah.tv, ah.seq);

		io++;
		total_bytes += nbytes;
        }

	gettimeofday(&end_time, NULL);
        printf("Connection closed by foreign host.\n");

	free(buf);
	print_statistics(SOCK_DGRAM, start_time, end_time, total_bytes, io);
}



struct addrinfo *getaddrlist(const char *host, const char *port, int flags, int family, int socktype) {

	int ret;
	struct addrinfo	hints, *addrlist;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = flags;
	hints.ai_family = family;	/* specify IPv4, v6, etc.	*/
	hints.ai_socktype = socktype;	/* specify UDP, TCP, etc.	*/


	ret = getaddrinfo(host, port, &hints, &addrlist);
	if(ret != 0) {
 		fprintf(stderr, "getaddrinfo failed\n");
		perror("");
		exit(1);
	}

	return addrlist;
}





int init_sock(struct addrinfo *ai) {

	const 	int on = 1;
	int	 fd;
	int ret;

	if (ai == NULL)
		return(-1);

	if ( (fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0 ) {
		fd = init_sock(ai->ai_next);
		return fd;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	check("setsockopts", ret);


	if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
		if(ai->ai_socktype == SOCK_STREAM) {
			ret = listen(fd, LISTENQ);
			check("listen", ret);
		}
		return fd;
	}
	else {
		ret = close(fd);
		check("close", ret);
		fd = init_sock(ai->ai_next);
		return fd;
	}
}




void insert_time_record(struct timeval my_time, struct timeval his_time, int seq) {

	struct s_time_record *record = (struct s_time_record*) malloc(sizeof(struct s_time_record));

	/* fill record */
	record->next = NULL;
	record->my_time = my_time;
	record->his_time = his_time;
	record->seq = seq;

	time_record_tail->next = record;
	time_record_tail = time_record_tail->next; /* time_record_tail points
						      to the end of the list */
}
void free_time_record(struct s_time_record *node) {
	if(node->next != NULL)
		free_time_record(node->next);

	free(node);
}


void print_statistics(int socktype, struct timeval start, struct timeval end, int total_bytes, int io) {
	int i;
	struct s_time_record *record;
	struct timeval tdiff, total_delay, avg_delay, sqrsum;// sdiv, tmp;
	int npackets = 0;
	double t_delay, t_avg, t_total;

	record = time_record_head.next;

	int last_seq = 1;
	struct s_seqlist *seqlist;

	total_delay.tv_sec = 0;
	total_delay.tv_usec = 0;
	sqrsum.tv_sec = 0;
	sqrsum.tv_usec = 0;

	while(record != NULL) {

		/*
		printf("%i ", record->seq);
		if(seqformat++ == 10) {
			printf("\n");
			seqformat = 0;
		}*/

		if(socktype == SOCK_DGRAM) {

			/* save potentially lost sequence numbers */
			for(i = last_seq + 1; i < record->seq; i++)
				insert_seq(i);

			/* saved sequence number found. Delete it from lost-seq-number list */
			if(last_seq > record->seq)
				delete_seq(record->seq);

			last_seq = record->seq;
		}



		tvsub(&tdiff, &(record->my_time), &(record->his_time)); /* delay */
		tvadd(&total_delay, &total_delay, &tdiff);	/* sum delay */


		npackets++;
		record = record->next;
	}

	avg_delay.tv_sec = total_delay.tv_sec / npackets;
	avg_delay.tv_usec = total_delay.tv_usec / npackets;

	/*
	//standard diviation:
	record = time_record_head.next;
	while(record != NULL) {
		tvsub(&tdiff, &(record->my_time), &(record->his_time)); //delay
		tvsub(&tmp, &tdiff, &avg_delay); // x1 - mü
		tvsqr(&tmp); // (x - mü)^2

		tvadd(&sdiv, &tmp);


		record = record->next;
	}*/

	tvsub(&tdiff, &end, &start);
	t_avg = tvtosec(&avg_delay);
	t_total = tvtosec(&tdiff);
	t_delay = tvtosec(&total_delay);

	printf("\n\nprinting statistics:\n" \
	       "--------------------------\n");
	printf("%i bytes received in %.2f seconds\n", total_bytes, t_total);
	printf("I/O calls: %i\n", io);
	printf("packets received: %i\n", npackets);
	printf("total delay: %.2f seconds\n", t_delay);
	printf("average delay: %f seconds\n", t_avg);

	/* printf("standard diviation: %ld seconds, %ld microseconds\n", sdiv.tv_sec / npackets,
							     sdiv.tv_usec / npackets); */



	/* print lost packets (only UDP) */
	if(socktype == SOCK_DGRAM) {

		seqlist = seqlist_head.next;
		if(seqlist == NULL)
			printf("No packet loss\n");
		else {
			int format = 0;
			int packetloss = 0;
			printf("\nPackets with the following sequence numbers are lost:\n\n");
			while(seqlist != NULL) {
				packetloss++;
				printf("%i ", seqlist->val);
				seqlist = seqlist->next;
				if(format++ == 10) {
					printf("\n");
					format = 0;
				}
			}
			printf("\n\nNumber of packets lost: %i\n", packetloss);

		}
	}
	printf("\n\n");

}


void insert_seq(int val) {
	seqlist_tail->next = (struct s_seqlist*) malloc(sizeof(struct s_seqlist));
	seqlist_tail = seqlist_tail->next;

	seqlist_tail->val = val;
	seqlist_tail->next = NULL;
}


void delete_seq(int val) {
	/* search for value */

	struct s_seqlist *node = seqlist_head.next;
	struct s_seqlist *prev_node = &seqlist_head;

	while(node != NULL) {
		if(node->val == val) {
			/* value found */
			prev_node->next = node->next;
			free(node);
		}
		prev_node = node;
		node = node->next;
	}
}
void free_seqlist(struct s_seqlist *node) {
	if(node->next != NULL)
		free_seqlist(node->next);
	free(node);
}

void tvsub(tdiff, t1, t0)
	struct timeval *tdiff, *t1, *t0;
{

	tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff->tv_usec < 0) {
		tdiff->tv_sec--; tdiff->tv_usec += 1000000;
	}
}

void tvadd(tsum, t0, t1)
	struct timeval *tsum, *t0, *t1;
{

	tsum->tv_sec = t0->tv_sec + t1->tv_sec;
	tsum->tv_usec = t0->tv_usec + t1->tv_usec;
	if (tsum->tv_usec > 1000000) {
		tsum->tv_sec++; tsum->tv_usec -= 1000000;
	}
}
double tvtosec(struct timeval *tv) {
	return (double)tv->tv_sec + ((double)tv->tv_usec) / 1000000;
}

void tvsqr(struct timeval *tv) {
	tv->tv_sec *= tv->tv_sec;
	tv->tv_usec *= tv->tv_usec;

	while((unsigned long)tv->tv_usec > 1000000) {
		tv->tv_sec++;  
        tv->tv_usec -= 1000000;
	}
}

/*
void tvmult(struct timeval *res, struct timeval *tv1, struct timeval *tv2) {
	res->tv_sec = tv1->tv_sec * tv2->tv_sec;
	res->tv_usec = tv1->tv_usec * tv2->tv_usec;

	while(res->tv_usec > 1000000) {
		res->tv_sec++; res->tv_usec -= 1000000;
	}
}*/

void check(char *msg, int num) {
        if(num < 0) {
         perror(msg);
         exit(0);
        }
}





