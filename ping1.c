#include<stdio.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h>
#include"HostNameToIp.h"
long long run=99999999;

int c,pack_rcv;
struct  timespec start,start1,end,end1;

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

// void printStats(){

//     time = ((end.tv_nsec-start.tv_nsec)/1000000)+((end.tv_sec-start.tv_sec)*1000);
//     packetLoss = ((c-pack_rcv)*100)/c;
//     char ch='%';
//     printf("\n\n----------ping statistics---------\n");
//     printf("%d packets transmitted, %d received, %f%c packet loss, time=%f ms\n\n",pck_trans,pck_rcv,packetLoss,ch,time);
    
// }




void stop_run(int l){
    run=0;
}

void set_run(long long u){
    run=u;
}

int main(int argc,char * argv[]){

    int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1)
	{
		perror("Failed to create socket");
		exit(1);
	}
    double time,packetLoss;
    char datagram[64] , source_ip[16] , desta[16];
	memset(datagram, 0, 64);

    int     TTL_def=51;
    


    if(setsockopt(s,SOL_IP,IP_TTL,&TTL_def,sizeof(TTL_def))!=0){

        printf("Error setting TTL value");
        return 0;
    }   
    struct sockaddr_in destAddr;
    convertHosttoIp(argv[1],desta,&destAddr);

    clock_gettime(CLOCK_MONOTONIC,&start);
    run=5;

    signal(SIGINT,stop_run);
    c=0,pack_rcv=0;
    while(run--){
    struct icmphdr *icmph = (struct icmphdr *) (datagram );


    printf("%s\n",desta);
    icmph->type=ICMP_ECHO;
    icmph->code=0;
    icmph->checksum=csum((unsigned short*)datagram,sizeof(datagram));
    icmph->un.echo.id = getpid();
    icmph->un.echo.sequence=c++;


    clock_gettime(CLOCK_MONOTONIC,&start1);
    

    if(sendto(s,datagram,sizeof(datagram),0,(struct sockaddr*)&destAddr,sizeof(destAddr))<=0)
        {
            printf("Sending failed\n");
           
        }

        else
        {
           // printf("s\n");
        }

        int rcv =recv(s, datagram, 64, 0);
		if(rcv<0)
		{
			printf("error in reading recv function\n");
            
			return -1;
		}
       
    
        struct icmphdr *icmp = (struct icmphdr *) (datagram );


        if(icmp->code!=0 && icmp->type!=69){
            printf("ERROR PACKET RECEIVED WITH ICMP CODE %d AND ICMP TYPE %d\n",icmp->code,icmp->type);
        }
        else{
            clock_gettime(CLOCK_MONOTONIC,&end1);
            time = ((end1.tv_nsec-start1.tv_nsec)/1000000)+((end1.tv_sec-start1.tv_sec)*1000);
            printf("64 bytes sent from %s icmp_seq=%d ttl=51 time=%f ms\n",desta,c,time);
            pack_rcv++;
        }
        
        //printf("%d %d",icmp->code,icmp->type);
    }

    clock_gettime(CLOCK_MONOTONIC,&end);

    time = ((end.tv_nsec-start.tv_nsec)/1000000)+((end.tv_sec-start.tv_sec)*1000);
    packetLoss = ((c-pack_rcv)*100)/c;
    char ch='%';
    printf("\n\n----------ping statistics---------\n");
    printf("%d packets transmitted, %d received, %f%c packet loss, time=%f ms\n\n",c,pack_rcv,packetLoss,ch,time);
    
    
        
}


    


