
#include<stdio.h>
#include<string.h> 
#include<sys/socket.h>	
#include<stdlib.h>
#include<errno.h> 
#include<netinet/tcp.h>	
#include<netinet/ip.h>
#include<linux/if_ether.h>
#include<arpa/inet.h>
#include<netdb.h>
#define TCP tcphdr
#include "regx.c"
#include"HostNameToIp.h"

struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct TCP tcp;
};

struct sockaddr_c       //sockaddr_in
{
    short           s_family;   //sin_family
    unsigned int    s_port;     //sin_port
    unsigned long   s_addr;     //struct in_addr
    char            s_zero[8];  //sin_zero
};


unsigned short csum(unsigned short *ptr,int size) 
{
	unsigned long int sum;
	unsigned short oddbyte;
	unsigned short int answer;

	sum=0;
	while(size>1)
    {
		sum+=*ptr++;
		size-=2;
	}
	if(size==1)
    {
		oddbyte=0;
		*((unsigned char*) & oddbyte)=*(unsigned char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0x0000ffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return answer;
}

int equal(char addr[], char arg[])
{	
	int flag = 0, i;
	for(i=0; ; i++)
    {
        if(addr[i]=='\0' || arg[i]=='\0') break;
        if(addr[i] != arg[i]) 
        {
            flag = 1;
            break;
        }
    }
    if(flag == 0 && addr[i] == '\0' && arg[i] == '\0')
        return 1;
    else
        return 0;


}


int main(int argc, char*argv[])
{
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
	{
		perror("Failed to create socket");
		exit(1);
	}

    char datagram[4096] , source_ip[16] , *data , *pseudogram, desta[16];
	memset(datagram, 0, 4096);
    short int port;

    struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_c sin, source, dest;
	struct sockaddr_in destAddr;
    struct pseudo_header psh;
    
    data = datagram + sizeof(struct iphdr) + sizeof(struct TCP);
	strcpy(data , "");

	strcpy(source_ip , "192.168.31.136");

    port = atoi(argv[2]);
	printf("%hd\n",port);
    
	if(is_Host(argv[1])){
		convertHosttoIp(argv[1],desta,&destAddr);

		printf("%s\n",desta);
	}
	else{
		strcpy(desta,argv[1]);
	}
    

	sin.s_family = AF_INET;
	sin.s_port = htons(port);
	sin.s_addr = inet_addr(desta);

    iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct TCP) + strlen(data);
	iph->id = htonl (54321);	
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;	
	iph->saddr = inet_addr (source_ip);
	iph->daddr = sin.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	tcph->source = htons (977);
	tcph->dest = htons (port);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct TCP) / 4;
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons(14600);	
	tcph->check = 0;	
	tcph->urg_ptr = 0;

    psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct TCP) + strlen(data) );
    psh.tcp = *tcph;
    
    int psize = sizeof(struct pseudo_header) + strlen(data);
	pseudogram = malloc(psize);

	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));

    tcph->check = csum( (unsigned short*) pseudogram , psize);

    int one = 1;
	const int *val = &one;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		perror("sendto failed");

	// else
	// 	printf ("Packet Sent. Length : %d \n" , iph->tot_len);

	struct sockaddr saddr;
	int saddr_len = sizeof (saddr);
	int i=0,flag=1;

	while(i<5){
		
		memset (datagram, 0, 4096);
		int rcv =recv(s, datagram, 4096, 0);
		if(rcv<0)
		{
			printf("error in reading recv function\n");
			return -1;
		}

		struct iphdr *ip = (struct iphdr *)(datagram );
		

		memset(&source, 0, sizeof(source));
		source.s_addr = ip->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.s_addr = ip->daddr;

		int iphdrlen = ip->ihl*4;
		//printf("Incoming packet\n\tsource ip      : %s\n",inet_ntoa(source.sin_addr));
		//printf("\tdestination ip : %s\n", inet_ntoa(dest.sin_addr));

		struct TCP *tcp=(struct TCP*)(datagram + iphdrlen);

        struct in_addr temp;
        temp.s_addr= source.s_addr;
		if((unsigned int)ip->protocol==6)
        {
			if(equal(inet_ntoa(temp) ,desta))
            {
				flag =0;

				printf("\nTCP header Flags:\n\tSYN: %d\n",tcp->syn);
				printf("\tRST: %d\n",tcp->rst);
				printf("\tPSH: %d\n",tcp->psh);
				printf("\tACK: %d\n",tcp->ack);
				printf("\tURG: %d\n",tcp->urg);
				if(tcp->rst) printf("This port is closed!\n");
				break;
			}

			if(tcp->rst) printf("This port is closed!\n");

		}

		i++;
	}

	if(flag) printf("This port is Filtered\n");
}
