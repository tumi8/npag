

void init_rawsocket		__P((sock_descriptor_t *fd, config_t*));
void init_rawsocket6	__P((sock_descriptor_t *fd, config_t*));

void fill_ip4hdr		__P((packet_buffer_t*, config_t*));
void fill_ip6hdr		__P((packet_buffer_t*, config_t*));

void set_ipsockopts		__P((packet_buffer_t*, config_t*));

