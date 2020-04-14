#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <arpa/inet.h> 
#include <netdb.h>

#define OPTSTRING "vi:"
#define DEFAULT_TTL 0

static struct option long_opts[] = {
  {"ttl", optional_argument, NULL, 't'}
};

void print_usage(char *progname) {
  fprintf(stderr, "A Ping application\n");
  fprintf(stderr, "Usage: %s [HOSTNAME] [OPTIONS]...\n\n", progname);
  fprintf(stderr, "\t-t [ttl]\tSpecify the TTL of the ICMP messages\n");
}

int domain_lookup(char *addr, char *ip, struct sockaddr_in *addr_con);

int main(int argc, char *argv[]) {
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
  
  char *ip = (char *) malloc(16 * sizeof(char));
  struct sockaddr_in addr_con;
  if(domain_lookup(domain, ip, &addr_con) != 0) {
    fprintf(stderr, "Error looking up domain\n");
    exit(EXIT_FAILURE);
  }
  
  printf("Pinging %s with a ttl of %d\n", domain, ttl);
  printf("IPv4 Address: %s\n", ip);
  
  
  
  // Free memory
  free(domain);
  free(ip);
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
