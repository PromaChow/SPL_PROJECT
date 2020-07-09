#include<stdio.h>	
#include<stdlib.h>	
#include<string.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include <fcntl.h> 
#include <unistd.h> 

int sock_raw;
FILE *logfile;



void PrintData(unsigned char *pay,int size)
{

    char *data= strstr(pay, "\r\n\r\n");
    if(data!=NULL)
    {
        fprintf(logfile ,"%s", data);

        for(unsigned char* i= data; i<pay+size; i++)
            fprintf(logfile, "%c", *i);

        fprintf(logfile, "\n");
    }
}

void ProcessPacket(unsigned char *buf,int size){
    struct iphdr *ip = (struct iphdr*) buf;
    int iphdrlen = ip->ihl*4;

    if((unsigned int)ip->protocol==6){
    struct tcphdr *tcp = (struct tcphdr*)(buf + iphdrlen); 
    fprintf(logfile,"\n");
    PrintData(buf+iphdrlen+tcp->doff*4,size-(iphdrlen+tcp->doff*4));

    }
    

}


int main(){
    int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    	logfile=fopen("Hi.txt","w");
	if(logfile==NULL) printf("Unable to create file.");
	printf("Starting...\n");
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof (saddr);
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		
		ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}