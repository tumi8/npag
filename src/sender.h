


int set_payload	__P((char *buf, int size, char *filename, int format, int pos));

typedef struct protocol_functions {
	void (*set_nethdr)(packet_buffer_t*, config_t*);
	void (*set_transhdr)(packet_buffer_t*, config_t*);
	void (*init_socket) (sock_descriptor_t *fd, config_t *conf);
} protofunc_t;


typedef struct adhdr {
	int payload_size;
	struct timeval tv;
	int seq;

	unsigned short mysize;
}adhdr_t;


typedef struct thread_param {
	config_t *conf;
	int id;
}thread_param_t;



void set_nethdr_NOT_DEFINED		__P(());
void set_transhdr_NOT_DEFINED	__P(());
void init_socket_NOT_DEFINED	__P(());
void sectotv				__P((double sec, struct timeval *tv));
void wait_timeval			__P((struct timeval *tv));
void init_generator			__P((protofunc_t *gen, config_t *conf));
void send_raw				__P((packet_buffer_t*, config_t*, protofunc_t*, int));
void send_kernel			__P((packet_buffer_t*, config_t*, protofunc_t*, int));
void init_sendinfo			__P((packet_buffer_t *sendinfo));
void empty_buffer		__P((packet_buffer_t *buffer));
int dec_available_buffer		__P((packet_buffer_t *buffer, int decrease_size));



extern int verbose;
extern int num_of_threads;
extern FILE *output;
extern int out;
extern pthread_cond_t master_wait;

pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MUTEX_LOCK(_P_) if (pthread_mutex_lock(&_P_)) { \
   			 perror("pthread_mutex_lock"); \
   			 pthread_exit(NULL); \
			} ;


#define MUTEX_UNLOCK(_P_) if(pthread_mutex_unlock(&_P_)) { \
  			  perror("pthread_mutex_unlock"); \
   			 pthread_exit(NULL); \
			};
