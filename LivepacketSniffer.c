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
#include<signal.h>
#define ETHER_LEN 6
FILE *pf,*part,*fp;
int c= 0,httpN=0,tcpN=0,udpN=0,sslN=0,icmpN=0;
// char num= 'A';
char FileName[1000];
int keepRunning=1;


void printStatistics(){
    printf("--------SUMMARY--------\n");
    printf("Total no. of\n\nTCP packets : %d\nUDP packets : %d\nHTTP packets : %d\nSSL packets : %d\n",tcpN,udpN,httpN,sslN);
}

void intHandler(int dummy){
    
    keepRunning=0;
    printStatistics();
}



void printHTTPPayload(unsigned char *pay,int size)
{


    part= fopen(FileName, "w");
    unsigned char *data= strstr(pay, "\r\n\r\n");
    if(data!=NULL)
    {
        // fprintf(fp ,"%s", data);
        // // printf("%s", data);
        // fprintf(part, "%s", data);

        for(unsigned char* i= data; i<pay+size; i++)
        {
            fprintf(pf, "%c", *i);
            // printf("%c", *i);
            fprintf(part, "%c", *i);
        }
        fprintf(pf, "\n");
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

}

void printPayload(unsigned char *pay, int len){
    
    for(int i=0;i<len;i++){

        if(i!=0 && i%16 == 0){
            fprintf(pf,"        ");

            for(int j=i-16;j<i;j++){

                if(pay[j]>=32 && pay[j]<=128){
                    fprintf(pf,"%c",(unsigned char)pay[j]);
                }
                    else fprintf(pf,".");
                
                
            }
            fprintf(pf,"\n");
        }

        if(i%16==0)
        fprintf(pf," ");
        fprintf(pf,"%02x",(unsigned int)pay[i]);

        if(i== len-1)
        {
            for(int j=0;j<15-i%16;j++){
                fprintf(pf,"   ");
            }
            fprintf(pf,"       ");

            for(int j=i-i%16;j<=i;j++){
                if(pay[j]>=32 && pay[j]<=128)
                {
                    fprintf(pf,"%c",(unsigned char)pay[j]);
                    
                }
                else
                {
                    fprintf(pf,".");
                }
                
            }

            fprintf(pf,"\n\n");
        }
    }
}



void processPackets(unsigned char *buffer,int length)
{
  
    struct iphdr *ip = (struct iphdr*) buffer;

    struct sockaddr_in IPsource,IPdest;

    memset(&IPsource,0,sizeof(IPsource));
    memset(&IPdest,0,sizeof(IPdest));

    IPsource.sin_addr.s_addr = ip->saddr;
    IPdest.sin_addr.s_addr =ip->daddr;
    unsigned int ver = (unsigned int)ip->version;
    unsigned int iphdrlen = (unsigned int)ip->ihl*4;
    unsigned int protocol = (unsigned int)ip->protocol;


    fprintf(pf,"-------IP HEADER-------\n");
    fprintf(pf,"Source IP : %s\n",inet_ntoa(IPsource.sin_addr));
    fprintf(pf,"Destination IP : %s\n",inet_ntoa(IPdest.sin_addr));
    fprintf(pf,"IP Version : %d\n",ver);
    fprintf(pf,"IP Header Length : %d\n",iphdrlen);
    fprintf(pf,"Protocol : %d\n",protocol);
    fprintf(pf,"Type of Service : %d\n",(unsigned int)ip->tos);
    fprintf(pf,"Checksum : %d\n",ntohs(ip->check));
    fprintf(pf,"Identification : %d\n",ntohs(ip->id));
    fprintf(pf,"TTL : %d\n\n",(unsigned int)ip->ttl);




    if(protocol==6){
    tcpN++;
    struct tcphdr *tcp = (struct tcphdr*)(buffer+iphdrlen);
    unsigned int tcphdrlen = (unsigned int) (tcp->doff*4);
    fprintf(pf,"-------TCP HEADER-------\n");
    fprintf(pf,"Source Port : %d\n",ntohs(tcp->source));
    fprintf(pf,"Destination Port : %d\n",ntohs(tcp->dest));
    fprintf(pf,"Sequence Number : %d\n",ntohl(tcp->th_seq));
    fprintf(pf,"TCP header Length : %d\n",tcphdrlen);
    fprintf(pf,"TCP flags:\n");
    fprintf(pf,"URG : %d\n",(unsigned int)tcp->urg);
    fprintf(pf,"ACK : %d\n",(unsigned int)tcp->ack);
    fprintf(pf,"PSH : %d\n",(unsigned int)tcp->psh);
    fprintf(pf,"RST : %d\n",(unsigned int)tcp->rst);
    fprintf(pf,"SYN : %d\n",(unsigned int)tcp->syn);
    fprintf(pf,"FIN : %d\n",(unsigned int)tcp->fin);
    fprintf(pf,"Window Size : %d\n",ntohs(tcp->window));
    fprintf(pf,"Checksum : %d\n",ntohs(tcp->check));
    fprintf(pf,"Urgent Pointer : %d\n\n",(unsigned int)tcp->urg_ptr);


    fprintf(pf,"\n-------THE PAYLOAD--------\n");
    unsigned short payload_len= length - (iphdrlen+tcphdrlen);
    if(ntohs(tcp->source)==80 || ntohs(tcp->dest)==80){
    httpN++;
            
    
            // int header_size =  sizeof(struct ethhdr) + iphdrlen + tcp->doff*4;
            // unsigned char *payload= (unsigned char*)(buffer+/*SIZE_ETHER+*/iphdrlen+tcphdrlen);

            snprintf(FileName, 1000, "file%d.html", c++);
            printHTTPPayload(buffer+iphdrlen+tcphdrlen, payload_len);
            // printPayload(buffer, length);
            fprintf(pf,"\n\n\n");
    }


    else{

        printPayload(buffer+iphdrlen+tcphdrlen, payload_len);
        fprintf(pf,"\n\n\n");

    }
    
    if(ntohs(tcp->source)==443|| ntohs(tcp->dest)==443){
    sslN++;
    }

    }


    if(protocol==17){
        struct udphdr *udp = (struct udphdr*)(buffer+iphdrlen);

        unsigned short payload_len= length - (iphdrlen+ntohs(udp->len));

        fprintf(pf,"-------TCP HEADER-------\n");
        fprintf(pf,"Source Port : %d\n",ntohs(udp->source));
        fprintf(pf,"Destination Port : %d\n",ntohs(udp->dest));
        fprintf(pf,"Length : %d\n",ntohs(udp->len));
        fprintf(pf,"Checksum : %d\n",ntohs(udp->check));
        fprintf(pf,"\n-------THE PAYLOAD--------\n");

        printPayload(buffer+iphdrlen+ntohs(udp->len), payload_len);
        fprintf(pf,"\n\n\n");
    }
    if(protocol==1)
    icmpN++;
}
    



  










int Livepktcap(){
int sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct sockaddr saddr;
    int addrlen, data;

    if(sockfd<0)
    {
        printf("Failed to create socket\n");
    }

    pf=fopen("packetLog.txt","w+");
    signal(SIGINT, intHandler);
    unsigned char *buffer = (unsigned char *)malloc(65536);
    //int loop=20;
    while(keepRunning){

        //memset(&buffer,0,sizeof(buffer));
        addrlen=sizeof(struct sockaddr);
        data=recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);
        if(data<0)
        {
            printf("Receive failed\n");
            return 1;
        }

        //struct GlobalHeader *ghead = (struct GlobalHeader*)(buffer);
        printf("Running...\r");
        processPackets(buffer,data);
            // else
            // printf("receiving\n");

    }

    
    

    close(sockfd);
}