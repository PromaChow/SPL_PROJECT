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
    unsigned int tSec;  /* timestamp seconds */
    unsigned int tuSec; /* timestamp microseconds */
    unsigned int ocLen; /* number of octets of packet saved in file */
    unsigned int packLen;  //actual length of packet
};

struct EthernetHeader
{
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short int ethType;
};

struct IP
{
    unsigned char source[4];
    unsigned char destination[4];
};




int main()
{
    struct GlobalHeader ghead;
    struct PacketHeader phead;
    struct EthernetHeader ehead;
    struct IP ip;
    
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

    fread(&c, sizeof(char), 1, pf); //taking IP Version Number;
    c=c>>4;
    printf("IP Version Number: %d\n",(int)c);

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
}




