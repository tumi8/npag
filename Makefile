
CC = gcc
CFLAGS = -g -Wall -O3
LDFLAGS = -lpthread
LD = gcc
OBJS = main.o sender.o checksum.o automata.o states.o packet_buffer.o tcp_module.o udp_module.o icmp_module.o ip_module.o
PROG = npag
PROG2 = npag_rec

all:  $(PROG2) $(PROG) *.h *.c

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $<
	

$(PROG2): npag_rec.o
	$(LD) $(LDFLAGS) npag_rec.o -o $(PROG2)

npag_rec.o: npag_rec.c
	$(CC) $(CFLAGS) -c npag_rec.c
	
clean:
	/bin/rm $(PROG) $(PROG2) $(PROG2).o $(OBJS) 
