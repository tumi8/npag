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

#include <stdio.h>
#include <pthread.h>
#include <string.h> /* strcpy, memset */
#include <stdlib.h> /* malloc */
#include <signal.h>
#include <unistd.h> //get_pid
#include <sys/time.h>
#include <time.h>

#include "memory.h"
#include "config.h"




/* maximum length of configuration file name */
//#define MAXFILENAME	20

/* some prototype definitions */
void wait_for_threads	__P(());
void* exec_thread			__P((void *traffic));
void start_automata		__P((config_t *conf, FILE *fp));
static void usage			__P(());
void sig_handler(int x);

void reg_table_init();
void register_functions();

/* condition variable */
pthread_cond_t master_wait = PTHREAD_COND_INITIALIZER;
pthread_mutex_t master_mutex = PTHREAD_MUTEX_INITIALIZER;


#define TRUE 1
#define FALSE 0

int verbose = 0;
int num_of_threads = 0;
FILE *output;
int out = 0;

uint stat_psentcount = 0;
uint stat_psentsize = 0;
struct timeval stat_starttime = {0,0};


typedef struct thread_param {
	config_t *conf;
	int id;
}thread_param_t;



    

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  
   taken from http://www.delorie.com/gnu/docs/glibc/libc_428.html
*/

int timeval_subtract (struct timeval* result, struct timeval* x, struct timeval* y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}


void print_stats()
{
    printf("Statistics:\n");
    printf("Total number of packets sent: %u\n", stat_psentcount);
    printf("Total size of data sent: %u\n", stat_psentsize);

    struct timeval endtime;
    struct timeval difftime;
    gettimeofday(&endtime, 0);
    timeval_subtract(&difftime, &endtime, &stat_starttime);
    float dtime = difftime.tv_sec+(float)difftime.tv_usec/1000000;
    printf("Elapsed time: %.3f seconds\n", dtime);
    printf("Average bandwidth used: %.3f MByte/s\n", stat_psentsize/dtime/1024/1024);
    printf("Average packet rate: %.1f packets/s\n", (float)stat_psentcount/dtime);
}

int main(int argc, char**argv) {

	pthread_t p_thread;
	config_t *conf;
	thread_param_t *th_param;
	char filename[MAXFILENAME];
	char output_file[MAXFILENAME];
	FILE *fp;

	/* read input parameters */
	if(argc < 3) {
		usage();
	}
	argv++; argc--;
	while( argc > 0 && argv[0][0] == '-' )  {
		switch (argv[0][1]) {
			case 'f': /* next string specifies a filename */
				strncpy(filename,&argv[1][0] , MAXFILENAME);
				argv++; argc--; /* skip filename */
				break;
			case 'v':
				verbose = 1;
				if(argv[0][2] == 'v')
					verbose = 2;
				break;
			// steffi: hier "fast" parameter einfuegen
			case 'o': /* next string specifies a filename */
				out = 1;
				strncpy(output_file,&argv[1][0] , MAXFILENAME);
				argv++; argc--; /* skip output filename */
				break;
			default:
				usage();
		};
		argv++; argc--;
	}


	if(out) {
		output = fopen(output_file, "a");
		if(!output) {
			fprintf(stderr, "Failed opening file for output %s: ", output_file);
			perror("");
		}
	}

    /* setup signal handler */
	struct sigaction sig;
	sig.sa_handler=sig_handler;
	sig.sa_flags=SA_RESTART;
	sigemptyset(&sig.sa_mask);
	if (sigaction(SIGINT, &sig, NULL) != 0) 
    {
        perror("failed to set signal handler\n");
        exit(2);
    }


	/* open script file for reading */
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Failed opening file %s: ", filename);
		perror("");
		exit(1);
	}

	/* read the script file */
	fprintf(stdout, "Reading configuration file...\n");

	conf = cmalloc(sizeof(config_t));
	/*conf = (config_t*) cmalloc(sizeof(config_t));*/

	/* the automata reads the script language from the
	 * file and fills the conf structure  */
	start_automata(conf, fp);
	
	fprintf(stdout, "File is OK\n\n");

	/* close script file */
	if (fclose(fp)) {
    		perror("Failed closing file ':");
	}

	reg_table_init();
	register_functions();
	fprintf(stdout, "Starting threads...\n");
	/* every conf specifies a single stream. The next stream
	 * is specified in conf->next. For every stream a thread is
	 * created */
	 conf = conf->next;
	while(conf != NULL) {
		th_param = cmalloc(sizeof(thread_param_t));
		/* th_param = (thread_param_t*) cmalloc(sizeof(thread_param_t));*/
		th_param->conf = conf;
		th_param->id = num_of_threads + 1;
		num_of_threads++;
		pthread_create(&p_thread, NULL, exec_thread, th_param);
		conf = conf->next;		
	}
	fprintf(stdout, "Done.\n\n");
	/* main waits for the threads to finish their work */
	//TODO You need a mutex here .. after reading num_of_threads
	//  another thread could be chosen...
	if(num_of_threads > 0)
		wait_for_threads();

    print_stats();
	return 0;
}



void wait_for_threads() {
	pthread_mutex_lock(&master_mutex);
	pthread_cond_wait(&master_wait, &master_mutex);
	pthread_mutex_unlock(&master_mutex);
}



static void usage() {
	printf("Usage: npag -f [config file] [-options]\n\n" \
			"Options: \n"\
			"\t-v verbose output\n" \
			"\t-vv even more outout\n"\
			"\t-o [filename] specifies an output filename. Raw packets are\n" \
			"\t              printed into the file in HEX format\n"
	 );
	exit(0);	
}









/* Reads 'size' characters from file 'filename' (starting at position 'pos')
   into buffer 'buf'.
   Return:  The number of characters written to the buffer.

   If 'filename' is empty, 'size' random characters are generated.
 */
int set_payload(char *buf, int size, char *filename, int format, int pos) {
	int cwrite = 0; /* number of characters written to buffer until now */
	int isRand = 0; // TODO this should be boolean

	
	if(strcmp(filename, "") == 0) isRand = 1;
	else isRand = 0;
	
	if(!isRand) {
		FILE *fp;
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "%i: ** WARNING ** : Failed opening file '%s' to read payload. "\
			                "Generating a random payload! \n" ,getpid(), filename);
			isRand = 1;
		}
		else {
			/* opening file succeeded */
			int c;

			/* goto position pos (skip pos characters) */
			while(pos != 0) {
				c = fgetc(fp);
				if(c == EOF) {
					ungetc(c, fp);
					break;
				}
				pos--;
			}
						
			if(format == HEX) {
				//fprintf(stderr, "IS_HEX...\n");
				while(cwrite < size) {
					int val;
					char hex[2];
					fgets(hex, 3, fp);
					//fprintf(stderr, "hex = %s\n", hex);
					val = strtol(hex, (char**)NULL, 16);
				
					*(buf + cwrite) = (char)val;
					//skip blank
					fgetc(fp);
					cwrite++;
				}

			}
			else {
				/* read characters into buffer */
				while(cwrite < size) {
					c = fgetc(fp);
					if(c == EOF) break;
					*(buf + cwrite) = c;
					cwrite++;
				}
			}


		}
	}

	/* No filename specified. Generate a random payload */
	if(isRand) {
		int i;
		for(i = 0; i < size; ++i) {
			*(buf + cwrite) = (rand() % 70) + 50;
			cwrite++;
		}
	}

	if(cwrite < size) {
		fprintf(stderr, "%i: ** WARNING ** : The payload size was specified to be %i bytes but the file contains only" \
		" %i bytes\n", getpid(), size, cwrite);
	}
	return cwrite;
}


void sig_handler(int x)
{
    fprintf(stderr, "caught SIGINT, exiting ...\n");
    print_stats();

	exit(1);
}
