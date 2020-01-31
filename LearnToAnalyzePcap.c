#include<stdio.h>
#include <arpa/inet.h>

struct GlobalHeader
{
    unsigned int       magicNumber;
    unsigned short int versionMajor;
    unsigned short int versionMinor;
    int                time;
    unsigned int       sigfigs;
    unsigned int       snaplen;
    unsigned int       network;
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
    unsigned char      destination[6];
    unsigned char      source[6];
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
    char flg[6];
    
    FILE *pf= fopen("iit2.pcap","rb");

    // for(int it=0; it<2; it++)
    // {

    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);

    printf("Magic number: %x\n",ghead.magicNumber);
    printf("Version: %x.%x\n",ghead.versionMajor, ghead.versionMinor);
    printf("Time: %x\n",ghead.time);
    printf("Sigfig: %x\n",ghead.sigfigs);
    printf("snaplen: %x\n",ghead.snaplen);
    printf("network: %x\n",ghead.network);

    for(int it=0; !feof(pf); it++)
    {

    printf("pack#%d:\n",it+1);
     fread(&phead, sizeof(struct PacketHeader), 1, pf);
    // for(int x=0;x<8;x++)
    //     c=fgetc(pf);

    // fread(&phead.packLen,sizeof(unsigned int), 1, pf);

    printf("length of packet: %d\n",phead.ocLen);

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
    //printf("%dhihi\n",len);
    for(int i=0;i<8;i++)
        fread(&c, sizeof(char), 1, pf);
    fread(&protocol, sizeof(char), 1, pf); //taking protocol
    fread(&g, sizeof(unsigned short), 1, pf);
    fread(&ip.source, sizeof(unsigned char)*4, 1, pf);
    fread(&ip.destination, sizeof(unsigned char)*4, 1, pf);

    if(protocol==6) printf("this is TCP protocol\n");
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
    /*while(i<len){
        ch=fgetc(pf);
        printf("here");
    }*/
   
    //fread(&a,sizeof(unsigned int),1,pf);
    fread(&T,sizeof(struct TCP),1,pf);
    printf("SOURCE PORT: %d\n",ntohs(T.srcport));
    printf("DESTINATION PORT : %d\n",ntohs(T.destport));
    
    int j= 0;
    //T.tcp_flag=T.tcp_flag>>2;
    for(int i=32;i>=1;i=i>>1)
    {
        if(T.tcp_flag & i) flg[j++]= 1;
        else flg[j++]= 0;
    }




    // for(int i=0;i<6;i++)
    //     printf("%d\t",flg[i]);

    printf("URG : %d\n",flg[0]);
    printf("ACK : %d\n",flg[1]);
    printf("PSH : %d\n",flg[2]);
    printf("RST : %d\n",flg[3]);
    printf("SYN : %d\n",flg[4]);
    printf("FIN : %d\n",flg[5]);
    //printf("WINDOW SIZE \n%d\n",ntohs(T.tcp_win));

    for(int bb=0; bb<phead.ocLen-54;bb++)
        c=fgetc(pf);

    }

}



