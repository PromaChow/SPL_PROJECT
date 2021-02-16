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
#include <inttypes.h>


#define ETHER_LEN 6
#define Black 40
#define Red 41 
#define Green 42 
#define Yellow 43
#define Blue 44
#define Magenta 45
#define Cyan 46
#define White 47
#define reset "\033[0m"
#define print(p,c) printf("\033[1m\033[%dm\033[%dm",p,c)
#define refresh() printf("%s",reset)

char handshake_type[21][20]={"HELLO REQUEST","CLIENT HELLO","SERVER HELLO","","","","","","","","","CERTIFICATE","SERVER KEY EXCHANGE","CERTIFICATE REQUEST","SERVER DONE","CERTIFICATE VERIFY","CLIENT KEY EXCHANGE","","","","FINISHED"};


FILE *pf,*part,*fp;
int c= 0,httpN=0,tcpN=0,udpN=0,sslN=0,icmpN=0;
// char num= 'A';
char FileName[1000];
int keepRunning=1;
int packetNo=0;
char state[100];


struct SSL{
    char rec_type[40];
    char version[20];
    char length[3];
    
};
struct SSL tls_info;



void printStatistics(){
    //printf("%s--------SUMMARY--------\n",KYEL);
    //printf("Total no. of\n\n%sTCP packets : %d\n%sUDP packets : %d\n%sHTTP packets : %d\n%sSSL packets : %d\n",KRED,tcpN,KBLU,udpN,KMAG,httpN,KCYN,sslN);
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


int getSSLinfo(unsigned char *p,int len){
    
    if(len<5) return 0;
    int record_protocol = (unsigned int)p[0];
    int ver1 = (unsigned int)p[1], ver2 = (unsigned int)p[2];
    
  

    if(record_protocol == 20){
        strcpy(tls_info.rec_type,"Content Type : Change Cipher Spec");
    }

    else if(record_protocol == 21){
       strcpy( tls_info.rec_type,"Content Type : Alert");
    }

    else if(record_protocol == 22){
        strcpy(tls_info.rec_type,"Content Type : Handshake");
    }
    else if(record_protocol == 23){
        strcpy(tls_info.rec_type,"Content Type : Application Data");
    }
    else{
        return 0;
    }

    //version
    if(ver1 == 3 && ver2 == 0){
        strcpy(tls_info.version,"Version : SSL 3.0");
    }

    else if(ver1 == 3 && ver2 == 1){
        strcpy(tls_info.version,"Version : TLS 1.1");
    }

    else if(ver1 == 3 && ver2 == 2){
       strcpy( tls_info.version,"Version : TLS 1.2");
    }

    else if(ver1 == 3 && ver2 == 3){
        strcpy(tls_info.version,"Version : TLS 1.3");
    }

    

    
    return 1;

}



void processPackets(unsigned char *buffer,int length)
{
    packetNo++;
    int color;
    fprintf(pf,"PACK# %d\n",packetNo);
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
    color = Yellow;
    struct tcphdr *tcp = (struct tcphdr*)(buffer+iphdrlen);
    unsigned int tcphdrlen = (unsigned int) (tcp->doff*4);
    fprintf(pf,"-------TCP HEADER-------\n");
    fprintf(pf,"Source Port : %d\n",ntohs(tcp->source));
    fprintf(pf,"Destination Port : %d\n",ntohs(tcp->dest));
    fprintf(pf,"Sequence NUmber : %" PRIu32, ntohl(tcp->th_seq));
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

    
    char tm[20] = "TCP";
    int fl = 0;
    
    refresh();

    fprintf(pf,"\n-------THE PAYLOAD--------\n");
    unsigned short payload_len= length - (iphdrlen+tcphdrlen);
    printPayload(buffer+iphdrlen+tcphdrlen, payload_len);
    fprintf(pf,"\n\n\n");
    if(ntohs(tcp->source)==80 || ntohs(tcp->dest)==80){
    
    httpN++;
            
            color = Blue;
            // int header_size =  sizeof(struct ethhdr) + iphdrlen + tcp->doff*4;
            // unsigned char *payload= (unsigned char*)(buffer+/*SIZE_ETHER+*/iphdrlen+tcphdrlen);

            snprintf(FileName, 1000, "file%d.html", c++);
            printHTTPPayload(buffer+iphdrlen+tcphdrlen, payload_len);
            // printPayload(buffer, length);
            fprintf(pf,"\n\n\n");
            fl = 1;
            print(37,color);
            strcpy(tm,"HTTP");
            printf("%-20s%-20s%-20s%-20d%-20d\n\n",inet_ntoa(IPsource.sin_addr),inet_ntoa(IPdest.sin_addr),tm,ntohs(tcp->source),ntohs(tcp->dest));
            fl = 1;
    }


   
    else if((ntohs(tcp->source)==443|| ntohs(tcp->dest)==443) && (getSSLinfo(buffer+iphdrlen+tcphdrlen,payload_len))){

    
    color = Cyan;
    sslN++;
    strcpy(tm,"SSL");
    print(30,color);
    char temp[] = "Length : ";
    printf("%-20s%-20s%-20s%-20d%-20d%-20s% -20s %s%x%x\n\n",inet_ntoa(IPsource.sin_addr),inet_ntoa(IPdest.sin_addr),tm,ntohs(tcp->source),ntohs(tcp->dest),tls_info.rec_type,tls_info.version,temp,(unsigned int)tls_info.length[0],(unsigned int)tls_info.length[1]);
    refresh();
    fl = 1;
    
    }
    
    
    if(fl==0){
    print(31,color);
    printf("%-20s%-20s%-20s%-20d%-20d\n\n",inet_ntoa(IPsource.sin_addr),inet_ntoa(IPdest.sin_addr),tm,ntohs(tcp->source),ntohs(tcp->dest));
    refresh();
    }
    }


    if(protocol==17){
        
        color = Magenta;
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
        print(37,color);
        printf("%s %s  UDP  %d  %d \n\n",inet_ntoa(IPsource.sin_addr),inet_ntoa(IPdest.sin_addr),ntohs(udp->source),ntohs(udp->dest));
        refresh();

    }
    
    if(protocol==1)
    icmpN++;
    sleep(3);
   // printf("%sTCP  : %d  %sUDP : %d  %sHTTP  : %d  %sSSL  : %d\r",KRED,tcpN,KBLU,udpN,KMAG,httpN,KCYN,sslN);
}




int Livepktcap(){
int sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct sockaddr saddr;
    int addrlen, data;

    if(sockfd<0)
    {
        printf("Failed to create socket\n");
    }
    printf("\033[5m\033[1m\033[3m\033[%dm",Green);
    printf("Starting....\n\n");
    refresh();
    
    pf=fopen("packetLog.txt","w+");
    signal(SIGINT, intHandler);
    unsigned char *buffer = (unsigned char *)malloc(65536);
        int p = 30;
        char tm[] = "IP Source Address";
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s",tm);
        refresh();

        strcpy(tm,"IP Dest Address");
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s",tm);
        refresh();

        strcpy(tm,"Protocol");
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s",tm);
        refresh();

        strcpy(tm,"Source Port");
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s",tm);
        refresh();

        strcpy(tm,"Dest Port");
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s",tm);
        refresh();

        strcpy(tm,"Info");
        printf("\033[1m\033[3m\033[%dm\033[%dm",p,White);
        printf("%-20s\n",tm);
        refresh();
    //int loop=20;
    while(keepRunning){

        //memset(&buffer,0,sizeof(buffer));
        addrlen=sizeof(struct sockaddr);
        data=recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);
        if(data<0)
        {
           // printf(green());
            printf("Receive failed\n");
            return 1;
        }

        //struct GlobalHeader *ghead = (struct GlobalHeader*)(buffer);
        //system("COLOR 02");
        //printf("Running...\r");
        

        processPackets(buffer,data);
            // else
            // printf("receiving\n");

    }

    
    

    close(sockfd);
}