/* maximum length of a word in the script file */
#define MAXWORDSIZE	20

//enum e_state { BEGIN, STREAM, IP_PROTO, IP6_PROTO, TCP_PROTO, UDP_PROTO, ICMP_PROTO, ICMP6_PROTO, TRAFFIC, PATTERN };

enum e_states {BEGIN = 1, STREAM, TRAFFIC, BURST, IP, IP6, TCP, UDP, ICMP, ICMP6};


typedef struct automata {
	BOOL network_defined;
	BOOL transport_defined;
	BOOL traffic_defined;
	BOOL reset;
	int state;
}automata_t;



/* linked list */
struct s_node {
	int state; /* current state */
	int return_state; /* return to that state when work is done in current state */
	
	void (*init)(config_t *conf);
	void (*check)(config_t *conf);
	void (*read)(char *word, char *val, config_t *conf, automata_t *automata);
	struct s_node *next;	
}head;

struct s_change {
	int from_state;
	char *keyword;
	int to_state;
	
	struct s_change *next;
} change_head;



void add_state		__P((int state, void *init_f, void *read_f, void *exit_f));
void add_change_state	__P((int from_state, char *keyword, int to_state));
int get_next_state	__P((int cur_state, char *word));
struct s_node* get_node	__P((int cur_state));


void init_automata	__P(());
void start_automata	__P((config_t *conf, FILE *fp));
void reset_automata __P(());

void skip			__P((FILE *fp));
int get_next_word	__P((char *word, FILE *fp));
void get_pair_value	__P((char *val, FILE *fp));











