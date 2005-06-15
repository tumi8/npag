

void init_tcpsocket		__P((sock_descriptor_t *fd, config_t*));
void init_tcpip6socket	__P((sock_descriptor_t *fd, config_t*));
void set_tcpsockopts	__P((packet_buffer_t*, config_t*));
void fill_tcphdr		__P((packet_buffer_t*, config_t*));

