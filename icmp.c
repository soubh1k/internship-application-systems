#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <math.h>

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

void handle_interrupt(int sig) {
	// SIGINT
	interrupt=1;
}

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

void ping(int sockfd, struct sockaddr_in *dest, char *ip_addr, char*hostname) {
	struct sockaddr_in receiver;

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

	gettimeofday(&start, NULL);
	while(++counter) {
		// Packet init
		struct timeval start_pkt, end_pkt;
	

		struct icmphdr hdr;
		bzero(&hdr, sizeof(hdr));

		hdr.type = ICMP_ECHO;
		hdr.code = 0;
		hdr.un.echo.id = htons(ID); /* identifier */
		hdr.un.echo.sequence = htons(counter); /* sequence no */

		// We don't modify the packet message. It is all zeros

		// Calculate checksum by first setting all checksum bits to 0
		hdr.checksum = 0; 
		// Checksum is calculated using 2 byte blocks
		hdr.checksum = checksum((short *)&hdr, sizeof(hdr));
		
		sleep(PING_DELAY);

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

		gettimeofday(&end_pkt, NULL);
		if(interrupt)
			break;

		if(status<=0 && counter>1) {
			fprintf(stderr, "Didn't receive packet.\n");
		}

		else {
			received++;
			if(packet_sent) {
				long seconds = (end_pkt.tv_sec - start_pkt.tv_sec);
				long micros = ((seconds * 1000000) + end_pkt.tv_usec) - (start_pkt.tv_usec);
				double millis = seconds*1000.0 + micros/1000.0;
				mini = MIN(mini, millis);
				maxi = MAX(maxi, millis);
				tsum += millis;
				tsum_2 += millis*millis;

				fprintf(stdout, "%d bytes from %s: icmp_seq=%d ttl=%d time=%0.1f ms\n", PING_BYTES, ip_addr, counter, TTL, millis);
			}
		}

	}
	gettimeofday(&end, NULL);

	long seconds = (end.tv_sec - start.tv_sec);
	long micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);
	double millis = seconds*1000.0 + micros/1000.0;

	average = tsum/(counter-1);
	tsum /= (counter-1);
	tsum_2 /= (counter-1);
	std_dev = sqrt(tsum_2 - tsum*tsum);

	fprintf(stdout, "\n--- %s ping statistics ---\n", hostname);
	double pkt_loss = (transmitted-received)/transmitted*100;
	fprintf(stdout, "%d packets transmitted, %d received, %0.0f%% packet loss, time %0.0fms\n", transmitted, received, pkt_loss, millis);
	fprintf(stdout, "rtt min/avg/max/mdev = %0.3f/%0.3f/%0.3f/%0.3f ms\n", mini, maxi, average, std_dev);
}

int main(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Enable root privilege.\n USAGE: %s <hostname>\n", argv[0]);
		return -1;
	}

	struct sockaddr_in server;
	char *ip_addr;

	// DNS lookup

	ip_addr = dns(argv[1], &server);
	if(ip_addr == NULL) {
		fprintf(stderr, "DNS lookup failed.\n");
		return -1;
	}

	fprintf(stdout, "PING: %s (%s) %d bytes of data.\n", argv[1], ip_addr, PING_BYTES);

	// Create socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0) {
		fprintf(stderr, "Cannot create socket\n");
		return -1;
	}

	signal(SIGINT, handle_interrupt);

	ping(sockfd, &server, ip_addr, argv[1]);

	return 0;
}