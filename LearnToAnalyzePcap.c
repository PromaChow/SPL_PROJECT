#include<stdio.h>
#include <arpa/inet.h>

struct GlobalHeader
{
    unsigned int magicNumber;
    unsigned short int versionMajor;
    unsigned short int versionMinor;
    int time;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int network;
};

struct PacketHeader
{
    unsigned int tSec;  
    unsigned int tuSec; 
    unsigned int ocLen; 
    unsigned int packLen;  
};

struct EthernetHeader
{
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short int ethType;
};

struct IP
{   unsigned char IHL;
    unsigned char source[4];
    unsigned char destination[4];
};
struct TCP{
    unsigned short int srcport;
    unsigned short int destport;
    unsigned int       seqNum;
    unsigned int       ackNUm;
    unsigned char      tcp_resoff;
    unsigned char      tcp_flag;
    unsigned short int tcp_win;
    unsigned short int tcp_checksum;
    unsigned short int tcp_urgptr;

};




int main()
{
    struct GlobalHeader ghead;
    struct PacketHeader phead;
    struct EthernetHeader ehead;
    struct IP ip;
    struct TCP T;
    
    unsigned char c, protocol;
    unsigned short g;
    
    FILE *pf= fopen("iit2.pcap","rb");

    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);

    printf("Magic number: %x\n",ghead.magicNumber);
    printf("Version: %x.%x\n",ghead.versionMajor, ghead.versionMinor);
    printf("Time: %x\n",ghead.time);
    printf("Sigfig: %x\n",ghead.sigfigs);
    printf("snaplen: %x\n",ghead.snaplen);
    printf("network: %x\n",ghead.network);

    fread(&phead, sizeof(struct PacketHeader), 1, pf);

    printf("length of packet: %d\n",phead.packLen);

    fread(&ehead, sizeof(struct EthernetHeader), 1, pf);
    ehead.ethType= ntohs(ehead.ethType);

    printf("Destination Address:");
    for(int i=0; i<6; i++)
    {
        printf("%02x",ehead.destination[i]);
        if(i!=5)printf(":");
        else printf("\n");
    }
    printf("Source Address:");
    for(int i=0; i<6; i++)
    {
        printf("%02x",ehead.source[i]);
        if(i!=5)printf(":");
        else printf("\n");
    }
    printf("Ethernet type: %x\n",ehead.ethType);

    fread(&ip.IHL, sizeof(char), 1, pf); //taking IP Version Number;
    unsigned short p,len;
    p=ip.IHL >>4;
    len=(ip.IHL & 0x0f);
    printf("IP Version Number: %d\n",(int)p);
    printf("IP header length is %d\n",(int)len*4);

    for(int i=0;i<8;i++)
        fread(&c, sizeof(char), 1, pf);
    fread(&protocol, sizeof(char), 1, pf); //taking protocol
    fread(&g, sizeof(unsigned short), 1, pf);
    fread(&ip.source, sizeof(unsigned char)*4, 1, pf);
    fread(&ip.destination, sizeof(unsigned char)*4, 1, pf);

    if(protocol==6) printf("this is TCP\n");
    else printf("this is not TCP\n");
    printf("source IP:");
    for(int i=0; i<4; i++)
    {
        printf("%d",(int)ip.source[i]);
        if(i!=3) printf(".");
        else printf("\n");
    }
    printf("destination IP:");
    for(int i=0; i<4; i++)
    {
        printf("%d",(int)ip.destination[i]);
        if(i!=3) printf(".");
        else printf("\n");
    }
    int i=0;
    len=len*4;
    len=len-20;
    char ch;
    while(i<len){
        ch=fgetc(pf);

    }
   
    //fread(&a,sizeof(unsigned int),1,pf);
    fread(&T,sizeof(struct TCP),1,pf);
    printf("SOURCE PORT: %d\n",ntohs(T.srcport));
    printf("DESTINATION PORT : %d\n",ntohs(T.destport));
    int URG,ACK,PSH,RST,SYN,FIN;
    int bit;
     bit=(int)T.tcp_flag>>7;
    if(bit&1==1) URG=1; else URG=0; 
    bit=(int)T.tcp_flag>>6;

    if(bit&1==1)  ACK=1; else ACK=0; 
    
    bit=(int)T.tcp_flag>>5;
    if(bit&1==1)  PSH=1; else PSH=0;
 
     bit=(int)T.tcp_flag>>4;
    if(bit&1==1)  RST=1; else RST=0;
   
     bit=(int)T.tcp_flag>>3;
    if(bit&1==1) SYN=1; else SYN=0;
    bit=(int)T.tcp_flag>>2;
    if(bit&1==1) FIN=1; else FIN=0;

    printf("FLAGS:\nURG : %d\nACK : %d\nPSH : %d\nRST : %d\nSYN : %d\nFIN : %d\n",URG,ACK,PSH,RST,SYN,FIN);
   


    


    

}




