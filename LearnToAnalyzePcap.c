#include<stdio.h>
#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in_systm.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#define IPV4 0x0800
#define ARP  0x0806
#define Wake_On_Lane 0x0842


struct Global_header {
    unsigned int magic_number;
    unsigned short int version_major;
    unsigned short int version_minor;
    unsigned int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int network;
} ;


struct EthHeader{

    unsigned char source_addr[6];
    unsigned char dest_addr[6];
    unsigned short type;

};


struct IPHeader{
    unsigned char verIHL;
    unsigned char TOS;
    unsigned short int length;
    unsigned short int identification;
    //unsigned char flag;
    unsigned short offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr source;
    struct in_addr dest;

};

struct TCP{
    unsigned short int SportAddr,DportAddr;
    unsigned int seqNum;
    unsigned int AckNum;


};

struct header_start{
        unsigned int time_sec;
        unsigned int time_milisec;
        unsigned int length;
        unsigned int orig_len;
};


int main(){

    FILE *fp = fopen("iit2.pcap","r");
    struct Global_header G;
    struct header_start  H;
    struct EthHeader     E;
    struct IPHeader      I;
    struct TCP           T;

    if(fp==NULL)
    {
        printf("ERROR OPENING FILE\n");

    }

    //fread(&G,sizeof(struct Global_header),1,fp);
    fread(&G.magic_number,sizeof(unsigned int), 1, fp);
    fread(&G.version_major,sizeof(unsigned short int),1, fp);
    fread(&G.version_minor,sizeof(unsigned short int),1, fp);
    fread(&G.thiszone, sizeof(unsigned int), 1, fp);
    fread(&G.sigfigs, sizeof(unsigned int), 1, fp);
    fread(&G.snaplen, sizeof(unsigned int), 1, fp);
    fread(&G.network, sizeof(unsigned int), 1, fp);

    printf("Magic Number is %x\nVersion Major is %x\nVersion Minor is %x\nZone is %x\nSigfigs is %x\nSnaplen is %x\nNetwork is %x\n\n ",G.magic_number,G.version_major,G.version_minor,G.thiszone,G.sigfigs,G.snaplen,G.network);

    fread(&H,sizeof(struct header_start),1,fp);
    printf("Time in sec %x\n Length of the packet is %d\n\n", H.time_sec,H.length);


    fread(&E.source_addr,sizeof(unsigned char)*6,1,fp);

    printf("SOURCE ADDRESS ");
    for (int i = 0; i < 6; ++i) {
        printf("%02x", E.source_addr[i]);

        if(i<5)
        printf(":");

    }
    printf("\n");


    fread(&E.dest_addr,sizeof(unsigned char)*6,1,fp);

    printf("DESTINATION ADDRESS ");
    for (int i = 0; i < 6; ++i) {
        printf("%02x", E.source_addr[i]);
        if(i<5)
        printf(":");

    }
    printf("\n");


    fread(&E.type,sizeof(unsigned short),1,fp);

    E.type=ntohs(E.type);

    printf("ETHERNET TYPE IS %x\n", E.type);

    if(E.type==IPV4)
    printf("The ETHERNET TYPE IS IPV4\n");

    fread(&I.verIHL,sizeof(unsigned char),1,fp);
    unsigned short int version1,Length;


     char version=I.verIHL>>4;
    
     version1=(int)version;

    char headerLength=I.verIHL & 0x0f;
    Length=(int)headerLength;
    

    printf("HEADER LENGTH IS %d\n",headerLength);

    fread(&I.TOS,sizeof(unsigned char),1,fp);
    fread(&I.length,sizeof(unsigned short),1,fp);
    fread(&I.identification,sizeof(unsigned short),1,fp);
    //fread(&I.flag,sizeof(unsigned char),1,fp);
    fread(&I.offset,sizeof(unsigned short),1,fp);
    fread(&I.ttl,sizeof(unsigned char),1,fp);
    fread(&I.protocol,sizeof(unsigned char),1,fp);
    fread(&I.checksum,sizeof(unsigned short),1,fp);
    fread(&I.source,sizeof(struct in_addr),1,fp);
    fread(&I.dest,sizeof(unsigned  char)*4,1,fp);
    unsigned short protocol=(int)I.protocol;

    if(protocol==6)
    printf("THIS IS A TCP PROTOCOL\n");

    // for (int i = 0; i < 4; ++i) {
    //     printf("%d", I.source[i]);

    //     if(i<3)
    //     printf(":");

    // }
    // printf("\n");

    printf("IP Address is : %s", inet_ntoa(I.source));


    if(protocol==6){

        fread(&T.SportAddr,sizeof(unsigned short),1,fp);
        printf("%d\n",T.SportAddr);

        fread(&T.DportAddr,sizeof(unsigned short),1,fp);
        printf("%d\n",T.DportAddr);

    }


    

    









    


}





