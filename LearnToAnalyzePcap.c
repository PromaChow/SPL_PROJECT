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
{
    unsigned char IHL;
    unsigned char source[4];
    unsigned char destination[4];
};
struct TCP
{
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

struct UDP
{
    unsigned short int  srcport;
    unsigned short int  destport;
    unsigned short      len;
    unsigned short      udp_checksum;
};


int main()
{
    struct GlobalHeader ghead;
    struct PacketHeader phead;
    struct EthernetHeader ehead;
    struct IP ip;
    struct TCP T;
    struct UDP U;
    

    unsigned char c, protocol;
    unsigned short g;
    char flg[6];

    FILE *pf= fopen("iit2.pcap","rb");


    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);

    printf("Magic number: %x\n",ghead.magicNumber);
    printf("Version: %x.%x\n",ghead.versionMajor, ghead.versionMinor);
    printf("Time: %x\n",ghead.time);
    printf("Sigfig: %x\n",ghead.sigfigs);
    printf("snaplen: %x\n",ghead.snaplen);
    printf("network: %x\n",ghead.network);

    for(int it=0; !feof(pf); it++)
    {

        printf("\n%c[4mpack#%d:\n%c[0m",27, it+1, 27);
        fread(&phead, sizeof(struct PacketHeader), 1, pf);

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

        for(int i=0; i<8; i++)
            fread(&c, sizeof(char), 1, pf);
        fread(&protocol, sizeof(char), 1, pf); //taking protocol
        fread(&g, sizeof(unsigned short), 1, pf);
        fread(&ip.source, sizeof(unsigned char)*4, 1, pf);
        fread(&ip.destination, sizeof(unsigned char)*4, 1, pf); //54 bytes read from packet

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
        if(protocol==6)
        {
            printf("this is TCP protocol\n");
            fread(&T,sizeof(struct TCP),1,pf);
            printf("SOURCE PORT: %d\n",ntohs(T.srcport));
            printf("DESTINATION PORT : %d\n",ntohs(T.destport));

            int j= 0;
            //T.tcp_flag=T.tcp_flag>>2;
            for(int i=32; i>=1; i=i>>1)
            {
                if(T.tcp_flag & i) flg[j++]= 1;
                else flg[j++]= 0;
            }
            for(int i=0; i<6; i++)
                {
                    if(i==0)
                printf("URG : %d\n",flg[i]);

                 if(i==1)
                printf("ACK: %d\n",flg[i]);

                 if(i==2)
                printf("PSH : %d\n",flg[i]);

                 if(i==3)
                printf("RST : %d\n",flg[i]);

                 if(i==4)
                printf("SYN : %d\n",flg[i]);

                 if(i==5)
                printf("FIN : %d\n",flg[i]);


            //printf("\n%d\n",ntohs(T.tcp_win));
        }
        }

        else if(protocol==17)
        {
            printf("this is UDP protocol\n");
            fread(&U, sizeof(struct UDP), 1, pf);
            printf("SOURCE PORT: %d\n",ntohs(U.srcport));
            printf("DESTINATION PORT : %d\n",ntohs(U.destport));
           // printf("UDP length: %d\n ",ntohs(U.len));

            for(int i=0; i<12; i++)
                c= fgetc(pf);
        }

        else
        {
            if(protocol==0)printf("This is HOPOPT protocol");
            else if(protocol==1)printf("This is ICMP protocol");
            else if(protocol==2)printf("This is IGMP protocol");
            else if(protocol==3)printf("This is GGP protocol");
            else if(protocol==4)printf("This is IP-in-IP protocol");
            else if(protocol==5)printf("This is ST protocol");
            else if(protocol==7)printf("This is CBT protocol");
            else if(protocol==8)printf("This is EGP protocol");
            else if(protocol==9)printf("This is IGP protocol");
            else if(protocol==10)printf("This is BBN-RCC-MON protocol");
            else if(protocol==11)printf("This is NVP-II protocol");
            else if(protocol==12)printf("This is PUP protocol");
            else if(protocol==13)printf("This is ARGUS protocol");
            else if(protocol==14)printf("This is EMCON protocol");
            else if(protocol==15)printf("This is XNET protocol");
            else if(protocol==16)printf("This is CHAOS protocol");
            else if(protocol==18)printf("This is MUX protocol");
            else if(protocol==19)printf("This is DCN-MEANS protocol");
            else if(protocol==20)printf("This is HMP protocol");
            else printf("protocol number: %d\n",protocol);
            for(int i=0; i<20; i++)
                c= fgetc(pf);
        }
            

        for(int bb=0; bb<phead.ocLen-54; bb++)
            c=fgetc(pf);

    }

}