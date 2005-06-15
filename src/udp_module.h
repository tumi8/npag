

void fill_udphdr		__P((packet_buffer_t*, config_t*));
void init_udpsocket		__P((sock_descriptor_t *fd, config_t*));
void init_udpip6socket	__P((sock_descriptor_t *fd, config_t*));
void set_udpsockopts	__P((packet_buffer_t*, config_t*));

