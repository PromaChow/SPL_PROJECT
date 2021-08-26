#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "HostNameToIp.h"
#include "regx.h"
#include "Headers.h"
#include "colors.h"

int start_sniffer();
char state[100];
char desta[16];
char host_name[100];
int port, open_port = 0, closed_port = 0, filtered_port = 0;

int get_local_ip(char *buffer)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	const char *kGoogleDnsIp = "8.8.8.8";
	int dns_port = 53;

	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);

	int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr *)&name, &namelen);

	const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
}

unsigned short csum(unsigned short *ptr, int size)
{
	unsigned long int sum;
	unsigned short oddbyte;
	unsigned short int answer;

	sum = 0;
	while (size > 1)
	{
		sum += *ptr++;
		size -= 2;
	}
	if (size == 1)
	{
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0x0000ffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

void service(int port)
{

	if (port == 25)
		strcpy(state, "SMTP");

	else if (port == 80)
		strcpy(state, "HTTP");

	else if (port == 443)
		strcpy(state, "HTTPs");

	else if (port == 20 || port == 21)
		strcpy(state, "FTP");

	else if (port == 23)
		strcpy(state, "TELNET");

	else if (port == 143)
		strcpy(state, "IMAP");

	else if (port == 3389)
		strcpy(state, "RDP");

	else if (port == 22)
		strcpy(state, "SSH");

	else if (port == 53)
		strcpy(state, "DNS");

	else if (port == 67 || port == 68)
		strcpy(state, "DHCP");

	else if (port == 110)
		strcpy(state, "POP3");

	else
		strcpy(state, " ");
}
struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

struct in_addr dest_ip;

int port_scan(char argv[], char ch, int p1, int p2)
{
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (s < 0)
	{
		printf("Error creating socket\n");
		exit(0);
	}

	char datagram[4096];

	struct iphdr *iph = (struct iphdr *)datagram;

	struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

	struct sockaddr_in dest;
	struct pseudo_header psh;

	int min_port, max_port;
	if (ch == 's')
	{
		max_port = min_port = p1;
	}
	else if (ch == 'r')
	{
		max_port = p2;
		min_port = p1;
	}

	struct sockaddr_in destAddr;

	if (is_Host(argv))
	{
		int p = convertHosttoIp(argv, desta, &destAddr);
		//printf("%s\n",desta);
		dest_ip.s_addr = inet_addr(desta);
		if (p == 0)
			return 0;

		strcpy(host_name, argv);
	}

	else
	{
		strcpy(desta, argv);
		dest_ip.s_addr = inet_addr(desta);
		IPtoHostName(desta, host_name);
	}

	int source_port = 43591;
	char source_ip[20];
	get_local_ip(source_ip);


	memset(datagram, 0, 4096);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htons(54321);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest_ip.s_addr;

	iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);

	tcph->source = htons(source_port);
	tcph->dest = htons(80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(14600);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	int one = 1;
	const int *val = &one;

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
		exit(0);
	}

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	char hs[] = "Host Name";
	char ip[] = "IP Address";
	char prt[] = "Port Number";
	char st[] = "State";
	char srv[] = "Service";

	printf("\033[1m\033[3m\033[%dm\033[%dm", 30, Yellow + 10);
	printf("%-20s%-20s%-20s%-20s%-20s\n\n", hs, ip, prt, st, srv);
	refresh();
	for (port = min_port; port <= max_port; port++)
	{
		service(port);
		tcph->dest = htons(port);
		tcph->check = 0;

		psh.source_address = inet_addr(source_ip);
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr));

		memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

		tcph->check = csum((unsigned short *)&psh, sizeof(struct pseudo_header));

		if (sendto(s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			printf("Error sending syn packet\n");
			exit(0);
		}
		start_sniffer();
	}
	printf("\n\n---------Final Statistics--------\nOpen Ports = %d, Filtered Ports = %d, Closed Ports = %d\n", open_port, filtered_port, closed_port);

	return 0;
}

int start_sniffer()
{
	int sock_raw;

	int saddr_size, data_size;
	struct sockaddr saddr;

	unsigned char *buffer = (unsigned char *)malloc(65536);

	fflush(stdout);

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return 1;
	}

	saddr_size = sizeof saddr;
	int i = 5;
	int flag = 1;
	while (i--)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		if (data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return 1;
		}

		struct iphdr *iph = (struct iphdr *)buffer;
		struct sockaddr_in source, dest;
		unsigned short iphdrlen;

		if (iph->protocol == 6)
		{
			struct iphdr *iph = (struct iphdr *)buffer;
			iphdrlen = iph->ihl * 4;

			struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

			memset(&source, 0, sizeof(source));
			source.sin_addr.s_addr = iph->saddr;

			memset(&dest, 0, sizeof(dest));
			dest.sin_addr.s_addr = iph->daddr;
			struct sockaddr_in IPsource;
			IPsource.sin_addr.s_addr = iph->saddr;
			//	printf("%d %s %d %d %d\n",(unsigned int)iph->protocol,inet_ntoa(IPsource.sin_addr),tcph->ack,tcph->syn,tcph->rst);

			if (source.sin_addr.s_addr == dest_ip.s_addr)
			{
				flag = 0;
				//printf("Hello\n");
				if (tcph->syn == 1 && tcph->ack == 1)
				{
					char tm[] = "Open";
					open_port++;
					print(Green); /*  */
					printf("%-20s%-20s%-20hd%-20s%-20s\n\n", host_name, desta, port, tm, state);
					fflush(stdout);
					refresh();
					i = 0;
				}
				else if (tcph->ack && tcph->rst)
				{
					char tm[] = "Closed";
					closed_port++;
					print(Red);

					printf("%-20s%-20s%-20hd%-20s%-20s\n\n", host_name, desta, port, tm, state);
					fflush(stdout);
					refresh();
					i = 0;
				}
			}
		}
	}
	if (flag)
	{
		filtered_port++;

		char tm[] = "Filtered";
		print(Magenta);
		printf("%-20s%-20s%-20hd%-20s%-20s\n\n", host_name, desta, port, tm, state);
		refresh();
	}

	fflush(stdout);
	return 0;
}
