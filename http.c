#include<stdio.h> 
#include<stdlib.h>    
#include<string.h>   
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>   
#include<netinet/ip.h>    
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include <fcntl.h> 
#include <unistd.h> 
// #include"hexHeader.h"

#define SIZE_ETHER 14
FILE *fp;
FILE *part;
int c= 0;
// char num= 'A';
char FileName[1000];





void printPayload(char *pay,int size)
{


    part= fopen(FileName, "w");
    char *data= strstr(pay, "\r\n\r\n");
    if(data!=NULL)
    {
        // fprintf(fp ,"%s", data);
        // // printf("%s", data);
        // fprintf(part, "%s", data);

        for(char* i= data; i<pay+size; i++)
        {
            fprintf(fp, "%c", *i);
            // printf("%c", *i);
            fprintf(part, "%c", *i);
        }
        fprintf(fp, "\n");
        fprintf(part,"\n");
    }
    // for(int i=0;i<size;i++)
    // {

    //     unsigned char ch= pay[i];

    //     if(pay[i]>=32 && pay[i]<=128)fprintf(fp,"%c",(unsigned char)pay[i]);
    //     else fprintf(fp, ".");

    //     // fprintf(fp, "%02x ", ch);

    //     if(i!=0 && i%16==0)
    //     fprintf(fp,"\n");

    // }
    fclose(part);
    // char str[1000]= "xdg-open ";
    // strcat(str, FileName);
    // if(strlen(data)>0)system(str);

}
void processPackets(unsigned char *buffer,int length)
{
   // struct sockaddr_in source,dest;

    struct iphdr *ip = (struct iphdr*)(buffer);

    unsigned short iphdrlen=ip->ihl*4;
    // unsigned short len=ip->tot_len;

    int protocol= (unsigned int)ip->protocol;

    if(protocol==6)
    {
    
        struct tcphdr *tcp = (struct tcphdr*)(buffer+ iphdrlen);
        unsigned int source = ntohs(tcp->source);
        unsigned int dest = ntohs(tcp->dest);
    //printf("%d %d\n",source,dest);
        if(source == 80 || dest == 80)
        {
   // printf("Source %u\nDest %u\n",ntohs(tcp->source),ntohs(tcp->dest));
            unsigned short tcphdrlen= tcp->doff*4;

            unsigned short payload_len= length - (iphdrlen+tcphdrlen);
    
            // int header_size =  sizeof(struct ethhdr) + iphdrlen + tcp->doff*4;
            // unsigned char *payload= (unsigned char*)(buffer+/*SIZE_ETHER+*/iphdrlen+tcphdrlen);

            snprintf(FileName, 1000, "Recievedfile%d.txt", c++);
            printPayload(buffer+iphdrlen+tcphdrlen, payload_len);
            // printPayload(buffer, length);
            fprintf(fp,"\n\n");

    
        }

    }
}
   




int main()
{
    int sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct sockaddr saddr;
    int addrlen, data;

    if(sockfd<0)
    {
        printf("Failed to create socket\n");

    }

    fp= fopen("html.txt","w");

    unsigned char *buffer = (unsigned char *)malloc(65536);
    //int loop=20;
    while(1){
        //memset(&buffer,0,sizeof(buffer));
        addrlen=sizeof(struct sockaddr);
        data=recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);
        if(data<0)
        {
            printf("Receive failed\n");
            return 1;
        }
        printf("Running...\r");
        processPackets(buffer,data);
            // else
            // printf("receiving\n");

    }

    close(sockfd);

    // for(int i=0;i<=k;i++){
    //     printf("%s\n%d\n%d\n",store[k].IP,store[k].SYN,store[k].SYN_ACK);
    // }



}