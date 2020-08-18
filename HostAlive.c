#include<stdio.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
//#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 




struct ICMP_packet{
    struct icmphdr icmp;
    char   payload[32-sizeof(struct icmphdr)];

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
 

int convertHosttoIp(char  hostname[],char ip[],struct sockaddr_in *destAddr){

    struct hostent *host;
    //char   *ptr;
    struct in_addr **address;

    host=gethostbyname(hostname);
    if(host == NULL)
    {
        printf("Error retrieving IP from hostname");
        return 0;
    }
    address = (struct in_addr **) host->h_addr_list;

    //  for(int i = 0; address[i] != NULL; i++)
    // {  
    //     strcpy(ip ,inet_ntoa(*address[i]) );
    //     return 0;
    // }
    strcpy(ip,inet_ntoa(*address[0]));
    (*destAddr).sin_family=host->h_addrtype;
    (*destAddr).sin_port=htons(Port);
    (*destAddr).sin_addr.s_addr=*(long*)host->h_addr;
    return 1;
}



int main(int argc,char* argv[]){

    int sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    struct sockaddr_in destIP;  


         
    return 0;


}


