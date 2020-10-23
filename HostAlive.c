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
 
double calculate_time(long int t1,long int t2){
     double time = (double)(t1- t2)/1000000;
}

double calculate_rtt(long int t1,long int t2,double t3){
  double rtt = (double)(t1 - t2)*1000 + t3;
}

void sendICMPpacket(int sockfd,struct sockaddr_in *destAddr){

    int     TTL_def=255;
    struct  timespec time_out,start,end,end1;
    struct  ICMP_packet packet;
    time_out.tv_sec=1;
    time_out.tv_nsec=0;
    struct sockaddr_in s_addr;
    int packet_transmitted=0,packet_received=0;
    clock_gettime(CLOCK_MONOTONIC, &start); 

    if(setsockopt(sockfd,SOL_IP,IP_TTL,&TTL_def,sizeof(TTL_def))!=0){

        printf("Error setting TTL value");
        return;
    }


    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&time_out,sizeof(time_out))!=0){

        printf("Error setting time_out value");
        return;
    }
    int loop=100000;
    while(loop--){
        int seq=0;
        int failed=0;
        memset(&packet,0,sizeof(packet));
        packet.icmp.type=ICMP_ECHO;
        packet.icmp.un.echo.id=getpid();
        packet.icmp.un.echo.sequence=seq++;
        for(int i=0;i<sizeof(packet.payload);i++){
            packet.payload[i]='*';
        }
        packet.icmp.checksum=csum((unsigned short*)&packet,sizeof(packet));
        if(sendto(sockfd,&packet,sizeof(packet),0,(struct sockaddr*)destAddr,sizeof(*destAddr))<=0)
        {
            printf("Sending failed\n");
            failed=1;
        }
        else{
            printf("Sending successful\n");
        }
        int length=sizeof(s_addr);
        double time,rtt;
        if(recvfrom(sockfd,&packet,sizeof(packet),0,(struct sockaddr*)&s_addr,&length)<=0){
            printf("Packet wasn't received\n");
            
        }
        else
        {
            printf("Packet received\n");
        clock_gettime(CLOCK_MONOTONIC, &end);
        packet_received++;


         time = calculate_time(end.tv_nsec,start.tv_nsec);
        
         rtt = calculate_rtt(end.tv_nsec,start.tv_nsec,time);

        //printf("\nICMP TYPE : %d\nICMP CODE: %d\n",packet.icmp.type,packet.icmp.code);
        }

        if(!failed){
          if(packet.icmp.type == 69 && packet.icmp.code==0){
             printf("32 bytes sent icmp_seq=%d ttl = 255 time= %f ms.\n", seq, rtt);
          }
          else{
            printf("Error packet received\n");
          }

        }

        clock_gettime(CLOCK_MONOTONIC, &end1);

        time = calculate_time(end1.tv_nsec,start.tv_nsec);
        double tot_time= calculate_rtt(end1.tv_nsec,start.tv_nsec,time);
        int packet_loss = (seq-packet_received)/seq;
        packet_loss*=100;
        char s[2];
        strcpy(s,"%");

        printf("\n\n------ping statistics-----\n");
        printf("%d packets transmitted, %d packets received,%d%s packet loss time %f ms",seq,packet_received,packet_loss,s,tot_time);

     }      
}

int main(int argc,char* argv[]){

    int sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    struct sockaddr_in destIP;  


    if(argc<2){
        printf("IP address or hostname wasn't given");
    }

    if(sockfd<0)
    {
        printf("Error establishing connection using socket");
        return 0;
    }

    // printf("%s",argv[1]);
    char ip[16];
    convertHosttoIp(argv[1],ip,&destIP);
    
    //printf("%d",(convertHosttoIp(argv[1],ip)));
    //printf("%s",ip);

    
    
    // while(*destIP!='\0')
    //     {
    //         printf("%c",*(destIP));
    //         *destIP++;
    //     }

    sendICMPpacket(sockfd,&destIP);
         
    return 0;


}


