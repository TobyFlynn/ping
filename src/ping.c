#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <arpa/inet.h> 
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#define OPTSTRING "t:"
#define DEFAULT_TTL 64
#define PKT_SIZE 64
#define PING_PERIOD 1000000

struct ping_pkt { 
    struct icmphdr hdr; 
    char msg[PKT_SIZE - sizeof(struct icmphdr)]; 
}; 

static struct option long_opts[] = {
  {"ttl", required_argument, NULL, 't'}
};

int ping_loop = 1;

// Timing functions
double elapsed_time(double *et);
void timing_start(double *timer);

// Network functions
int domain_lookup(char *addr, char *ip, struct sockaddr_in *addr_con);
//int reverse_lookup(char *ip);
unsigned short checksum (void *pkt, int len);
void snd_rcv_echo(int socket_handle, struct sockaddr_in *target_addr, char *ip, int ttl);

// Utility functions
void interruptHandler(int x) { ping_loop = 0; }

void print_usage(char *progname) {
  fprintf(stderr, "A Ping application\n");
  fprintf(stderr, "Usage: %s [HOSTNAME] [OPTIONS]...\n\n", progname);
  fprintf(stderr, "\t-t [ttl]\tSpecify the TTL of the ICMP messages\n");
}

int main(int argc, char *argv[]) {
  // Set interrupt handler
  signal(SIGINT, interruptHandler);
  
  // Check enough arguments have been provided
  if(argc <= 1) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  
  int domain_length = strlen(argv[1]);
  char *domain = (char *) malloc(domain_length * sizeof(char));
  strcpy(domain, argv[1]);
  
  int ttl = DEFAULT_TTL;
  
  // Get arguments
  int optc;
  while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF) {
    switch (optc) {
      case 't':
        ttl = atoi(optarg);
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  
  // Lookup domain name of target
  char *ip = (char *) malloc(16 * sizeof(char));
  struct sockaddr_in addr_con;
  if(domain_lookup(domain, ip, &addr_con) != 0) {
    fprintf(stderr, "Error looking up domain\n");
    exit(EXIT_FAILURE);
  }
  
  printf("Pinging %s with a ttl of %d\n", domain, ttl);
  printf("Resolved to IPv4 Address: %s\n", ip);
  
  // Create socket
  int shandle = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(shandle < 0) {
    fprintf(stderr, "Failed to create socket\n");
    exit(EXIT_FAILURE);
  }
  
  // Set TTL for socket
  if(setsockopt(shandle, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
    fprintf(stderr, "Failed to set TTL\n");
    exit(EXIT_FAILURE);
  }
  
  // Set timeout for the socket
  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  if(setsockopt(shandle, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != 0) {
    fprintf(stderr, "Failed to set socket timeout\n");
    exit(EXIT_FAILURE);
  }
  
  double total_timer = 0.0;
  timing_start(&total_timer);
  
  // Send and receive ICMP echo packets
  snd_rcv_echo(shandle, &addr_con, ip, ttl);
  
  double total_time = elapsed_time(&total_timer);
  
  printf("Total runtime: %f s\n", total_time);
  
  close(shandle);
  
  // Free memory
  free(domain);
  free(ip);
  
  return 0;
}

int domain_lookup(char *addr, char *ip, struct sockaddr_in *addr_con) {
  struct hostent *host_entity;
  
  if ((host_entity = gethostbyname(addr)) == NULL) { 
    return -1;
  }
  
  strcpy(ip, inet_ntoa(*((struct in_addr *) host_entity->h_addr)));
  
  addr_con->sin_family = host_entity->h_addrtype;
  addr_con->sin_port = htons(0);
  addr_con->sin_addr.s_addr = *((long *) host_entity->h_addr);
  
  return 0;
}

unsigned short checksum (void *pkt, int len) {
  unsigned short *buf = pkt;
  unsigned int sum = 0; 
  unsigned short result; 
  
  for (sum = 0; len > 1; len -= 2) {
    sum += *buf++; 
  }
  if (len == 1) { 
    sum += *(unsigned char*)buf; 
  }
  sum = (sum >> 16) + (sum & 0xFFFF); 
  sum += (sum >> 16); 
  result = ~sum; 
  return result; 
}

void snd_rcv_echo(int socket_handle, struct sockaddr_in *target_addr, char *ip, int ttl) {
  int num_sent = 0;
  int num_received = 0;
  while(ping_loop) {
    usleep(PING_PERIOD);
    
    // Create ICMP echo packet
    struct ping_pkt pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.type = ICMP_ECHO;
    pkt.hdr.un.echo.id = getpid();
    
    int i;
    for(i = 0; i < sizeof(pkt.msg) - 1; i++) {
      pkt.msg[i] = (char) i;
    }
    
    pkt.msg[i] = '\0';
    pkt.hdr.un.echo.sequence = num_sent;
    pkt.hdr.checksum = checksum(&pkt, sizeof(pkt));
    
    int sent = 1;
    
    // Start timer
    double timer = 0.0;
    timing_start(&timer);
    
    // Send packet
    if(sendto(socket_handle, &pkt, sizeof(pkt), 0, (struct sockaddr *) target_addr, sizeof(*target_addr)) <= 0) {
      fprintf(stderr, "Failed to send packet\n");
      sent = 0;
    }
    
    // Receive packet
    if(sent) {
      struct sockaddr_in rcv_addr;
      socklen_t addr_len = sizeof(rcv_addr);
      
      if(recvfrom(socket_handle, &pkt, sizeof(pkt), 0, (struct sockaddr *)&rcv_addr, &addr_len) <= 0) {
        fprintf(stderr, "Packet Lost: seq=%d\n", num_sent-1);
      } else {
        double time = elapsed_time(&timer) * 1000.0;
        
        if(!(pkt.hdr.type == 69 && pkt.hdr.code == 0)) {
          fprintf(stderr, "Error received unexpected packet: type %d code %d\n", 
                  pkt.hdr.type, pkt.hdr.code);
        } else {
          printf("Received %d bytes from %s \t seq=%d ttl=%d rtt=%f ms\n",
                 PKT_SIZE, ip, num_sent, ttl, time);
          num_received++;
        }
      }
      num_sent++;
    }
  }
  
  float loss = 100.0 - (((float)num_received / (float)num_sent) * 100.0);
  printf("\nOverall packet loss: %f %%\n", loss);
}

double elapsed_time(double *et) {
  struct timeval t;
  double old_time = *et;

  gettimeofday( &t, (struct timezone *)0 );
  *et = t.tv_sec + t.tv_usec*1.0e-6;

  return *et - old_time;
}

void timing_start(double *timer) {
  elapsed_time(timer);
}
