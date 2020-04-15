/*
Soubhik Rakshit
Cloudflare internship application

Compile with 
`gcc -Wall ping.c -o ping -lm`

Run as
sudo ./ping [-c count] cloudflare.com

count is the number of ping packets to send.
If count is 0 or count is absent, the loop will
repeat infinite times until SIGINT interrupt occurs.

Example usage:
sudo ./ping -c 10 cloudflare.com
sudo ./ping cloudflare.com

This application handles SIGINT interrupts to show statistics 
and gracefully close connections.

All time is shown as Wall Clock time.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <math.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX(a,b) ((a>b)?a:b)
#define MIN(a,b) ((a<b)?a:b)

#define PING_BYTES 64
#define PORT_NO 43543
#define PING_DELAY 1
#define TIMEOUT 2
#define MAX_HOST 1024
#define TTL 32
#define ID 5446

int interrupt = 0; // 1 if SIGINT
int count = 0;	// Number of ping requests. If 0, never stop

/* 
SIGINT triggers this function.
A global interrupt flag is switched on to let the program
know that it needs to gracefully kill itself.
*/
void handle_interrupt(int sig) {
	// SIGINT
	interrupt=1;
}

/*
Calculate checksum of ICMP header breaking it into several
16 byte (short) blocks.
*/
unsigned short checksum(short *data, size_t bytes) 
{
	if (bytes%2==1) {
  		fprintf(stderr, "ICMP_checksum: number of bytes %zu must be even\n", bytes);
		return -1;
	}

	unsigned short result; 
	unsigned int sum=0; 

	for(sum=0; bytes>1; bytes-=2)
		sum += *data++; 

	// Fold 4 byte sum to 2 bytes
	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16); 
	
	// Calculate ones complement
	result = ~sum; 
	return result;
}

/*
DNS lookup. Convert hostnames to IP addresses.
*/
char* dns(char *hostname, struct sockaddr_in *server) {
	struct hostent *host;
	char *ip_addr = (char *) malloc(sizeof(char)*MAX_HOST);

	// Resolve hostname
	host = gethostbyname(hostname);
	if(host == NULL) {
		fprintf(stderr, "Host not found\n");
		return '\0';
	}

	// Convert data from binary form to ip dot notation and 
	// store in server
	strcpy(ip_addr, inet_ntoa(*(struct in_addr *)host->h_addr));
	(*server).sin_family = host->h_addrtype;
	(*server).sin_addr.s_addr = *(uint32_t*) host->h_addr;
	(*server).sin_port = htons(PORT_NO);

	return ip_addr;
}

/*
Run the ping application. Print status of each packet.
Finally, upon interrupt, print statistics.
*/
void ping(int sockfd, struct sockaddr_in *dest, char *ip_addr, char*hostname) {
	struct sockaddr_in receiver;

	// Keep track of time
	struct timeval start, end;
	double mini=INT_MAX, maxi=0, average=0.0, std_dev;
	float tsum=0.0, tsum_2=0.0; // Used for calculating RTT std dev

	int status;
	socklen_t receiver_addr_size;
	int transmitted=0, received=0;

	int ttl_val = TTL;
	socklen_t ttl_val_size = sizeof(ttl_val);

	// Modify TTL in IP layer
	status = setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, ttl_val_size);
	if(status != 0) {
		fprintf(stderr, "Failed to modify TTL in socket options\n");
		return;
	}	

	struct timeval timeout;
	bzero(&timeout, sizeof(timeout));
	timeout.tv_sec = TIMEOUT;

	// Modify timeout
	status = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if(status != 0) {
		fprintf(stderr, "Failed to modify timeout in socket options\n");
		return;
	}

	// Loop for multiple packets
	int counter=0;

	// Get total start time.
	gettimeofday(&start, NULL);
	while(count==0 || counter<count) {
		counter++;
		// Packet init
		struct timeval start_pkt, end_pkt;
	
		// Create ICMP header
		struct icmphdr hdr;
		bzero(&hdr, sizeof(hdr));

		hdr.type = ICMP_ECHO;
		hdr.code = 0;
		hdr.un.echo.id = htons(ID); /* identifier */
		hdr.un.echo.sequence = htons(counter); /* sequence no */

		// We don't modify the packet message. It is all zeros

		// Calculate checksum by first setting all checksum bits to 0
		hdr.checksum = 0; 
		// Checksum is calculated using 2 byte blocks (short)
		hdr.checksum = checksum((short *)&hdr, sizeof(hdr));
		
		sleep(PING_DELAY);

		// Start timer for particular packet
		gettimeofday(&start_pkt, NULL);

		// Send ICMP_ECHO packet
		status = sendto(sockfd, &hdr, sizeof(hdr), 0,
						(struct sockaddr *) dest, sizeof(*dest));

		int packet_sent = 1;
		if(status<=0) {
			fprintf(stdout, "status: %d\n", status);
			fprintf(stderr, "Cannot send packet.\n");
			packet_sent = 0;
		}
		else
			transmitted++;

		receiver_addr_size = sizeof(receiver);

		// Receive reply
		status = recvfrom(sockfd, &hdr, sizeof(hdr), 0, 
						  (struct sockaddr *)&receiver, &receiver_addr_size);

		// Get end time of partiular packet
		gettimeofday(&end_pkt, NULL);
		if(interrupt)
			break;

		if(status<=0 && counter>1) {
			fprintf(stderr, "Didn't receive packet.\n");
		}
		else {
			// Receive packet only if packet was transmitted
			if(packet_sent) {
				received++;
				long seconds = (end_pkt.tv_sec - start_pkt.tv_sec);
				long micros = ((seconds * 1000000) + end_pkt.tv_usec) - (start_pkt.tv_usec);
				double millis = micros/1000.0;
				mini = MIN(mini, millis);
				maxi = MAX(maxi, millis);
				tsum += millis;
				tsum_2 += millis*millis;

				fprintf(stdout, "%d bytes from %s: icmp_seq=%d ttl=%d time=%0.1f ms\n", PING_BYTES, ip_addr, counter, TTL, millis);
			}
		}

	}
	// Get total end time
	gettimeofday(&end, NULL);

	long seconds = (end.tv_sec - start.tv_sec);
	long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);
	double millis = micros/1000.0;

	// fprintf(stdout, "counter : %d, received : %d\n", counter, received);

	average = tsum/received;
	tsum /= received;
	tsum_2 /= (received);
	std_dev = sqrt(tsum_2 - tsum*tsum);

	if(interrupt)
		transmitted--; // Remove last packet which was interrupted


	fprintf(stdout, "\n--- %s ping statistics ---\n", hostname);
	double pkt_loss = 1.0*(transmitted-received)/transmitted*100;
	fprintf(stdout, "%d packets transmitted, %d received, %0.0f%% packet loss, time %0.0fms\n", transmitted, received, pkt_loss, millis);
	fprintf(stdout, "rtt min/avg/max/mdev = %0.3f/%0.3f/%0.3f/%0.3f ms\n", mini, maxi, average, std_dev);

	status = close(sockfd);
	if(status!=0) {
		fprintf(stderr, "Failed to close socket\n");
		return;
	}
}

/*
Parge CLI arguments into optional count and hostname
*/
void argparse(int argc, char *argv[], int *count, char **hostname) {
	int m, n, l, ch;

	for(n=1; n<argc; n++) {
		switch(argv[n][0]) {
			case '-':
				l=strlen(argv[n]);
				for(m=1; m<l; m++) {
					ch = (int)argv[n][m];
					switch(ch) {
						case 'c':
							n++;
							*count = atoi(argv[n]);
							break;
						default:
							fprintf(stderr, "USAGE: sudo %s [-c count] <hostname>\n", argv[0]);
					}
				}
				break;
			default:
				*hostname = argv[n];
		}
	}
}

int main(int argc, char *argv[]) {
	int c=0;
	char *hostname=NULL;
	argparse(argc, argv, &c, &hostname);

	if(argc < 2) {
		fprintf(stderr, "USAGE: sudo %s [-c count] <hostname>\n", argv[0]);
		return -1;
	}

	count = c; // Change global

	struct sockaddr_in server;
	char *ip_addr;

	// DNS lookup
	ip_addr = dns(hostname, &server);
	if(ip_addr == NULL) {
		fprintf(stderr, "DNS lookup failed.\n");
		return -1;
	}

	fprintf(stdout, "PING: %s (%s) %d bytes of data.\n", hostname, ip_addr, PING_BYTES);

	// Create socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0) {
		fprintf(stderr, "Cannot create socket\n");
		return -1;
	}

	// Handle interrupts
	signal(SIGINT, handle_interrupt);

	// Run ping loop
	ping(sockfd, &server, ip_addr, hostname);

	return 0;
}