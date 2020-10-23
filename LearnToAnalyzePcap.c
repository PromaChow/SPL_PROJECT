#include<stdio.h>
#include <arpa/inet.h>
#include<string.h>
#define MAX 100000


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

struct flood{
    int IP[4];
    unsigned long int syn;
    unsigned long int syn_ack; 
};

struct flood track[MAX];
long long spoof[MAX],s=0,tcp=0,udp=0,icmp=0;
long long track_bound=-1,spoof_bound=-1;


int find_duplicate(long long k){

    for(int i=0;i<=spoof_bound;i++){
        if(spoof[i]==k)
        return 1;
    }
    return 0;

}

int similar(int arr[],int Addr[]){
    for(int i=0;i<4;i++){
        if(arr[i]!=Addr[i])
        return 0;
    }
    return 1;
}

void change(int IPAddr[],int flag){

    long long k,f=0;
    for(int i=0;i<=track_bound;i++){
        if(similar(IPAddr,track[i].IP)){
            if(flag == 1){
                k = track[i].syn;
                k++;
                track[i].syn = k;
                f=1;  
                
            }
            else{
                k = track[i].syn_ack;
                k++;
                track[i].syn_ack = k;
                f=1;
            }

            if((track[i].syn-20)>=track[i].syn_ack)
                {
                    if(!find_duplicate(i)){
                        spoof_bound++;
                        spoof[spoof_bound]=i;
                    }
                }
                break;
        }


    }

        if(f==0)
        {
            track_bound++;

            for(int i=0;i<4;i++){
                track[track_bound].IP[i]=IPAddr[i];
            }
            if(flag==1)
            track[track_bound].syn=1;
            else
            {
                track[track_bound].syn_ack=1;
            }
            
        }
    

}


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

    FILE *pf= fopen("SYNFlood.pcap","rb");
    FILE *fp =fopen("packetLog.txt","w+");
    FILE *ff =fopen("Stas.txt","w+");

    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);

    fprintf(fp,"Magic number: %x\n",ghead.magicNumber);
    fprintf(fp,"Version: %x.%x\n",ghead.versionMajor, ghead.versionMinor);
    fprintf(fp,"Time: %x\n",ghead.time);
    fprintf(fp,"Sigfig: %x\n",ghead.sigfigs);
    fprintf(fp,"snaplen: %x\n",ghead.snaplen);
    fprintf(fp,"network: %x\n",ghead.network);

    printf("Running.....\n");
    printf("Analysing packets\n");

    for(int it=0; !feof(pf); it++)
    {

        fprintf(fp,"\n\npack#%d: ",it+1);
        fread(&phead, sizeof(struct PacketHeader), 1, pf);

        fprintf(fp,"length of packet: %d\n",phead.ocLen);

        fread(&ehead, sizeof(struct EthernetHeader), 1, pf);
        ehead.ethType= ntohs(ehead.ethType);

        fprintf(fp,"Destination Address:");
        for(int i=0; i<6; i++)
        {
            fprintf(fp,"%02x",ehead.destination[i]);
            if(i!=5)fprintf(fp,":");
            else fprintf(fp,"\n");
        }
        fprintf(fp,"Source Address:");
        for(int i=0; i<6; i++)
        {
            fprintf(fp,"%02x",ehead.source[i]);
            if(i!=5)fprintf(fp,":");
            else fprintf(fp,"\n");
        }
        fprintf(fp,"Ethernet type: %x\n",ehead.ethType);

        fread(&ip.IHL, sizeof(char), 1, pf); //taking IP Version Number;
        unsigned short p,len;
        p=ip.IHL >>4;
        len=(ip.IHL & 0x0f);
        fprintf(fp,"IP Version Number: %d\n",(int)p);
        fprintf(fp,"IP header length is %d\n",(int)len*4);

        for(int i=0; i<8; i++)
            fread(&c, sizeof(char), 1, pf);
        fread(&protocol, sizeof(char), 1, pf); //taking protocol
        fread(&g, sizeof(unsigned short), 1, pf);
        fread(&ip.source, sizeof(unsigned char)*4, 1, pf);
        fread(&ip.destination, sizeof(unsigned char)*4, 1, pf); //54 bytes read from packet

        fprintf(fp,"source IP:");

        int arr[4],arr2[4];
        int lm=0;
        
        for(int i=0; i<4; i++)
        {
            fprintf(fp,"%d",(int)ip.source[i]);
            //printf("%d\n",(int)ip.source[i]);
            arr[lm++]=(int)ip.source[i];
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n");
        }
        lm=0;
        fprintf(fp,"destination IP:");
        for(int i=0; i<4; i++)
        {
            fprintf(fp,"%d",(int)ip.destination[i]);
            arr2[lm++]=(int)ip.destination[i];
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n");
        }
        int i=0;
        len=len*4;
        len=len-20;
        char ch;
        if(protocol==6)
        {
            tcp++;
            fprintf(fp,"this is TCP protocol\n");
            fread(&T,sizeof(struct TCP),1,pf);
            fprintf(fp,"SOURCE PORT: %d\n",ntohs(T.srcport));
            fprintf(fp,"DESTINATION PORT : %d\n",ntohs(T.destport));

            int j= 0;
            //T.tcp_flag=T.tcp_flag>>2;
            for(int i=32; i>=1; i=i>>1)
            {
                if(T.tcp_flag & i) flg[j++]= 1;
                else flg[j++]= 0;
            }
            int ur=0,ac=0,ps=0,rs=0,sy=0,fi=0;
            for(int i=0; i<6; i++)
                {
                if(i==0)
                {
                    fprintf(fp,"URG : %d\n",flg[i]);
                    ur=flg[i];
                }

                 if(i==1){

                    fprintf(fp,"ACK: %d\n",flg[i]);
                    ac=flg[i];
                }

                 if(i==2){
                    fprintf(fp,"PSH : %d\n",flg[i]);
                    ps=flg[i];
                 }

                 if(i==3){
                    fprintf(fp,"RST : %d\n",flg[i]);
                    rs=flg[i];
                 }

                 if(i==4)
                {
                    fprintf(fp,"SYN : %d\n",flg[i]);
                    sy=flg[i];
                    
                }

                 if(i==5)
                {
                    fprintf(fp,"FIN : %d\n",flg[i]);
                    fi=flg[i];
                }

                if(sy==1 && ac==1 && ur==0 && fi==0 && ps==0 && rs==0){
                    change(arr,2);
                }
                else if(sy==1 && ac==0 && ur==0 && fi==0 && ps==0 && rs==0){
                    change(arr2,1);
                }


            //printf("\n%d\n",ntohs(T.tcp_win));
        }
        }

        else if(protocol==17)
        {
            udp++;
            fprintf(fp,"this is UDP protocol\n");
            fread(&U, sizeof(struct UDP), 1, pf);
            fprintf(fp,"SOURCE PORT: %d\n",ntohs(U.srcport));
            fprintf(fp,"DESTINATION PORT : %d\n",ntohs(U.destport));
           // printf("UDP length: %d\n ",ntohs(U.len));

            for(int i=0; i<12; i++)
                c= fgetc(pf);
        }

        else
        {
            if(protocol==0)fprintf(fp,"This is HOPOPT protocol");
            else if(protocol==1)fprintf(fp,"This is ICMP protocol");
            else if(protocol==2)fprintf(fp,"This is IGMP protocol");
            else if(protocol==3)fprintf(fp,"This is GGP protocol");
            else if(protocol==4)fprintf(fp,"This is IP-in-IP protocol");
            else if(protocol==5)fprintf(fp,"This is ST protocol");
            else if(protocol==7)fprintf(fp,"This is CBT protocol");
            else if(protocol==8)fprintf(fp,"This is EGP protocol");
            else if(protocol==9)fprintf(fp,"This is IGP protocol");
            else if(protocol==10)fprintf(fp,"This is BBN-RCC-MON protocol");
            else if(protocol==11)fprintf(fp,"This is NVP-II protocol");
            else if(protocol==12)fprintf(fp,"This is PUP protocol");
            else if(protocol==13)fprintf(fp,"This is ARGUS protocol");
            else if(protocol==14)fprintf(fp,"This is EMCON protocol");
            else if(protocol==15)fprintf(fp,"This is XNET protocol");
            else if(protocol==16)fprintf(fp,"This is CHAOS protocol");
            else if(protocol==18)fprintf(fp,"This is MUX protocol");
            else if(protocol==19)fprintf(fp,"This is DCN-MEANS protocol");
            else if(protocol==20)fprintf(fp,"This is HMP protocol");
            else fprintf(fp,"protocol number: %d\n",protocol);
            for(int i=0; i<20; i++)
                c= fgetc(pf);
        }
            

        for(int bb=0; bb<phead.ocLen-54; bb++)
            c=fgetc(pf);

    }

    fprintf(ff,"TCP : %lld\nUDP : %lld\nICMP : %lld\n",tcp,udp,icmp);

    for(int i=0;i<=spoof_bound;i++){
        for(int j=0;j<4;j++){
            printf("%d ",track[i].IP[j]);

        }
        printf("\n");
    }



    printf("\n\nDONE!\n");



}