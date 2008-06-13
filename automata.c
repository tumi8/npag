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
#include <string.h>
#include <stdlib.h> //atof
#include "memory.h"

#include "config.h"
#include "automata.h"
#include "states.h"

//TODO if you change conf->ipproto you may not need this anymore ?!
#include <netinet/in.h> //IPPROTO_XXX


/* global variables */

int fp_line = 1; /* line of FILE pointer */
int word_line;	/* line of word that was read last */

//struct addrinfo **tmpip_src;
//struct addrinfo **tmpip_dst;
//int *tmpipproto;



/********************************************************************************
 * Deterministic finit automata. A word is read from the input file. The automata
 * is then fed with the word.
 ********************************************************************************/
void start_automata(config_t *conf, FILE *fp) {
	struct s_node *node = NULL;
	int next_state = 0;
	int last_state = 0;

	char word[MAXWORDSIZE], val[MAXWORDSIZE];
	automata_t automata;
	automata.state = BEGIN;


	reset_automata(&automata);
	init_automata();

	conf->traffic.pattern = NULL;


	while(get_next_word(word, fp) != EOF) {
		/* remember line of word */
		word_line = fp_line; 

	
		/* the closing bracket indicates that the current state ist finished with its work. The automata 
		 * should return to the the state that calls the current state */
		 if(strcmp(word, "}") == 0) {
			node = get_node(automata.state);
			if(node->check != NULL) {
				node->check(conf);
				//fprintf(stderr, "leaving state %i, calling check...\n", automata.state);
			}
			automata.state = node->return_state;	
			continue;
		}
		
		 next_state = get_next_state(automata.state, word);	
		 
		
		/* change state */
		if(next_state != -1) {
			
			/* before we change the state: call the check function of the last state */
		//	fprintf(stderr, "changing %i ==> %i \n", automata.state, next_state);
			node = get_node(automata.state);
			if(node != NULL) {
				if(node->check != NULL) {
					node->check(conf);
		//			fprintf(stderr, "check function called \n");
				}
			}
			
			last_state = automata.state;
			automata.state = next_state;
			node = get_node(automata.state);
			node->return_state = last_state;
		//	fprintf(stderr, "%i ==> %i\n", automata.state, last_state);
			if(node->init != NULL) {
				node->init(conf);
				/* a new conf structure could have been malloced ( node->init(conf) could be the 
				 * pointer to the function init_stream in states.c, which mallocs a new conf structure.
				 * conf sould always point to the last element in the linked list ) */ 
				while(conf->next != NULL)
					conf = conf->next;
			}
		}
		
		/* remain in current state */
		else {
			struct s_node *node;
			node = get_node(automata.state);
			if(node != NULL) {
				get_pair_value(val, fp);	
				node->read(word, val, conf, &automata);
			//	fprintf(stderr, "in state...automata.state = %i\n", automata.state);
			}
			else {
				fprintf(stderr, "INTERNAL ERROR: automata in unknown state (%i)\n", automata.state);
				exit(0);
			}	
			
		}
	}
	
	/* automata should end up in state BEGIN!! */
	if(automata.state != BEGIN) {
		fprintf(stderr, "ERROR: unexpected end of file, %i\n", automata.state);
		exit(0);	
	}
	//conf->next = NULL;

}

/********************************************************************************
 * Builds the automata. In the begining the automata is empty, i.e. number of 
 * states is zero. 
 ********************************************************************************/
void init_automata() {
		
	/* add some states */
	add_state(BEGIN, NULL, begin, check_begin);
	add_state(IP, init_ip, read_ip, check_ip);	
	add_state(TCP, init_tcp, read_tcp, check_tcp);
	add_state(UDP, init_udp, read_udp, check_udp);
	add_state(ICMP, init_icmp, read_icmp, check_icmp);
	add_state(ICMP6, init_icmp6, read_icmp6, check_icmp6);
	add_state(IP6, init_ip6, read_ip6, check_ip6);	
	
	add_state(STREAM, init_stream, read_stream, check_stream);
	add_state(TRAFFIC, init_traffic, read_traffic, check_traffic);
	add_state(BURST, init_pattern, read_pattern, check_pattern);
	
	/* specify when the automata should change the state */
	add_change_state(BEGIN, "stream", STREAM);
	add_change_state(STREAM, "ip", IP);
	add_change_state(STREAM, "tcp", TCP);
	add_change_state(STREAM, "udp", UDP);
	add_change_state(STREAM, "icmp", ICMP);
	add_change_state(STREAM, "icmp6", ICMP6);
	add_change_state(STREAM, "ip6", IP6);
	add_change_state(STREAM, "traffic", TRAFFIC);
	add_change_state(TRAFFIC, "burst", BURST);
	
}

/********************************************************************************
 * Adds a state to the automata. "new_state" is a unique value. The three parametes
 * "init_f", "read_f" and "check_f" spefify pointer to functions. "init_f" is called
 * when the state "new_state" is entered, "read_f" is called for execution the
 * the state and "check_f" is called when the state is exited.
 ********************************************************************************/
void add_state(int new_state, void *init_f, void *read_f, void *check_f) {
		
		struct s_node *node;
		node = &head;
		
		/* goto end of link list */
		while(node->next != NULL)
			node = node->next;
			
		node->next = cmalloc(sizeof(struct s_node));
		node = node->next;
		node->state = new_state;
		
		node->init = init_f;
		node->read = read_f;
		node->check = check_f;
		node->next = NULL;	
}

/********************************************************************************
 * Specifies when the automata should change the state. If the automata is in
 * state "from_state" and reads the word "keyword" it changes to state "to_state"
 ********************************************************************************/
void add_change_state(int from_state, char *keyword, int to_state) {
	struct s_change *change;
	change = &change_head;
	
	while(change->next != NULL) 
		change = change->next;
		
	change->next = cmalloc(sizeof(struct s_change));
	change = change->next;
	change->from_state = from_state;
	change->keyword = keyword;
	change->to_state = to_state;
	change->next = NULL;
}

/********************************************************************************
 * The automata should change the state with a specific keyword. This function
 * returns the state the automata should change to or -1 if it should remain
 * in the current state.
 ********************************************************************************/
int get_next_state(int cur_state, char *keyword) {
	struct s_change *change = &change_head;
	
	change = change->next;
	while(change != NULL) {
		if(cur_state == change->from_state)
			if(strcmp(keyword, change->keyword) == 0) {
				return change->to_state;
			}
				
		change = change->next;
	}
	return -1;
}

/********************************************************************************
 * Returns the implementation of the state. The returned node contains
 * the functions init_f, read_f and check_f that are called if the automata
 * enters / executes / exits the state "cur_state".
 ********************************************************************************/
struct s_node* get_node(int cur_state) {
	struct s_node *node = &head;
	node = node->next;
	while(node != NULL) {
		if(cur_state == node->state) {
			return node;
		}
		node = node->next;	
	}
	return NULL;
}

/********************************************************************************
 *	Resets the automata.
 ********************************************************************************/
void reset_automata(automata_t *automata) {
	automata->network_defined = FALSE;
	automata->transport_defined = FALSE;
	automata->traffic_defined = FALSE;
	automata->reset = FALSE;
	automata->state = BEGIN;
}


/* -------------------------------------------------------------------------------------
 				functions for parsing
----------------------------------------------------------------------------------------*/



/*************************************************************************
 *	Skips white characters and some other characters that are
 *	not of interest. Comments ( starting with # ) are skipped as well.
 *************************************************************************/
void skip(FILE *fp) {
	int c;
	BOOL check_white = TRUE;

	while(check_white) {
		fp_line--;
		do {
			c = fgetc(fp);
			fp_line++;
			/* skip these characters */
			while(c == ' ' || c == '\t' || c == '{' ||  c == ';') {
				c = fgetc(fp);
			}
		} while(c == '\n'); /* skip newline */
		/* while-post-condition: character found that we do not want to skip */

		check_white = FALSE;
		
		/* if we found a comment skip it */
		if(c == '#') {
			while(c != '\n' && c != EOF) {
				c = fgetc(fp);
			}
			fp_line++;
			check_white = TRUE; /* we have to check for white characters after
								   the comment again */
		}
	}

	/* give character back to stream */
	ungetc(c, fp);

}


/*************************************************************************
 *	Finds the next word and places it into *word. First all white characters
 *	and other characters that are not of interest are skipped (by calling
 *	the function skip). It then copys the first word it finds into *word.
 *************************************************************************/
int get_next_word(char *word, FILE *fp) {
	char buf[MAXWORDSIZE];
	int c;
	int i = 0;
//	char *str;

	skip(fp);

	c = fgetc(fp);
	if(c == EOF)
		return EOF;

	/* the characters in the while condition mark the end of a word */
	//while(c != ' ' && c != '\t' && c != '{' && c != ';' && c != '=' && c != '\n' && c != EOF) {
	do {
		buf[i] = c;
		i++;
		c = fgetc(fp);
	}while(c != ' ' && c != '\t' && c != '{' && c != ';' && c != '=' && c != '\n' && c != '}' && c != EOF);
	ungetc(c, fp);

	if(i > MAXWORDSIZE) {
		fprintf(stderr, "ERROR line %i: word too large. Either make the word smaller or increase MAXWORDSIZE!\n", word_line); 
		exit(0);
	}
    
	memcpy(word, buf, i);
	word[i] = '\0';
	
	/* do not return EOF since word is not emty */
	return 1;
}


/*******************************************************************************************
 *	Trys to find a word that is a 'pair value' of another word.
 *	Example:	port = 25;
 *			Here the word '25' is a pair value of word 'port'.
 *	The function assumes that the file pointer fp points to the first character that is
 *	located behind the first word of the pair value (behind 'port'). The function
 *	searches for a '=' character and places the word that comes after
 *	into *val.
 ********************************************************************************************/
void get_pair_value(char *val, FILE *fp) {

	char c;
	skip(fp);

	c = fgetc(fp);
	if(c == EOF) {
		ungetc(c, fp);
	}

	else if(c == '=') {
		get_next_word(val, fp);
	}
	else {
		ungetc(c, fp);
	}

}


