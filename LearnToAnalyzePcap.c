#include<stdio.h>
#include <arpa/inet.h>
#include<string.h>
#include <inttypes.h>
#include<sys/stat.h>
#define MAX 100000
FILE *pf,*fp,*ff;
FILE *ses_fp;
char ptr[65536];


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
    unsigned char  tos;
    unsigned short length;
    unsigned short id;
    unsigned short fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char source[4];
    unsigned char destination[4];
};

struct ARP{
    unsigned short int hardware_type;
    unsigned short int protocol;
    unsigned char hardware_size;
    unsigned char protocol_size;
    unsigned short int opcode;
    unsigned char  sender_MAC[6];
    unsigned char  sender_IP[4];
    unsigned char  target_MAC[6];
    unsigned char  target_IP[4];

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


struct http_ses{
    char filename[100];
    
    unsigned int IP_source[4];
    unsigned int IP_destination[4];
    unsigned short int  s_port;
    unsigned short int  d_port;
    unsigned int       first_seqNum;
    unsigned int prev_seq;
    unsigned int prev_ack;
    int chunked;
    int c;
    
}html_ses[1000];
int s_k=0;

struct flood track[MAX];
long long spoof[MAX],s=0,tcp=0,udp=0,icmp=0;
long long track_bound=-1,spoof_bound=-1;





void printPay(int len){
    unsigned char ch[16];
    char c;
    
    for(int i=0;i<len;i++){
        if(i!=0 && i%16==0){
            fprintf(fp,"                        ");
            for(int j=i-16;j<i;j++){
                if((unsigned int)ch[j%16]>=32 && (unsigned int)ch[j%16]<=126){
                fprintf(fp,"%c",ch[j%16]);
                ptr[j] = ch[j%16];
                }
                else
                {
                    fprintf(fp,".");
                    if((unsigned int)ch[j%16]==10) {
                        ptr[j] = '\n';
                    }
                    else if((unsigned int)ch[j%16]==13) ptr[j] = '\r';
                    else ptr[j] = '.';
                }
                
        }
        fprintf(fp,"\n");
        }
        
        
        ch[i%16]=fgetc(pf);
        fprintf(fp,"%02x ",(unsigned int)ch[i%16]);
        

        if(i== len-1)
        {
            for(int j=0;j<15-i%16;j++){
                fprintf(fp,"   ");
            }
            fprintf(fp,"                        ");

            for(int j=i-i%16;j<=i;j++){
                if((unsigned int)ch[j%16]>=32 && (unsigned int)ch[j%16]<=127)
                {
                    fprintf(fp,"%c",ch[j%16]);
                    ptr[j] = ch[j%16];
                    
                }
              else
                {
                    fprintf(fp,".");
                    if((unsigned int)ch[j%16]==10) { //replaced 0a
                        ptr[j] = '\n';
                    }
                    else if((unsigned int)ch[j%16]==13) ptr[j] = '\r'; //replaced 0d
                    else ptr[j] = '.';
                }
                
            }

        
    }
    }
    fprintf(fp,"\n\n");
    
}


void http_pay(int len,int http,struct http_ses http_session,int pd,int contains_pay){
    
    
    printPay(len);
    ptr[len]='\0';

    char *r;
    if(http==1){
      
        char type[10];
        r = strstr(ptr,"GET");
        if(r!=NULL){
            

           
            if(strstr(ptr,"text/html")!=NULL){
                strcpy(type,"html");
            }
            else if(strstr(ptr,"text/css")!=NULL){
                strcpy(type,"css");
            }
            else if(strstr(ptr,"text/javascript")!=NULL){
                strcpy(type,"js");
            }
        r = strstr(ptr,"Host:");
        if(r!=NULL){
            
            int l=r-ptr+6;
            
            int k=0;
            
            while(l<len && ptr[l]!='\r' && ptr[l+1]!='\n'){
                html_ses[s_k].filename[k++]=ptr[l++];
               
            }
            
            html_ses[s_k].filename[k]='\0';
            html_ses[s_k].c=1;
            char file_name[1000];
            
            //sprintf(file_name, "index.html", html_ses[s_k].filename );
            
            snprintf(file_name, 1000, "http_htmls/index_%d.%s",(s_k+1),type);
            ses_fp=fopen(file_name,"w+");
            chmod(file_name,S_IRWXO);
            if(ses_fp==NULL)
            printf("BRO U A STUPID FAILURE\n");
            html_ses[s_k].chunked = 0;
            html_ses[s_k].s_port = http_session.s_port;
            html_ses[s_k].d_port = http_session.d_port;
            html_ses[s_k].prev_seq = http_session.prev_seq;
            html_ses[s_k].prev_ack = http_session.prev_ack;
            html_ses[s_k].first_seqNum = http_session.prev_ack;
            for(int i=0;i<4;i++){
                html_ses[s_k].IP_source[i] = http_session.IP_source[i];
                html_ses[s_k].IP_destination[i]= http_session.IP_destination[i]; 
                }

            

           // printf("%s %d %d %u %u\n", html_ses[s_k].filename,html_ses[s_k].s_port,html_ses[s_k].d_port,html_ses[s_k].expecting_seqNum,html_ses[s_k].prev_seq);
            s_k++; 
        
        }
    }
    else{
        if(contains_pay){
          //   printf("hello\n");
            int j=-1;
            for(int i=0;i<s_k;i++){
               // printf("%d %d\n",http_session.d_port,html_ses[i].s_port);
                if(http_session.d_port == html_ses[i].s_port){
                    
                    j=i;
                }
                else {
                   
                    j=-1;
                    continue;
                }
              //  printf("%d %d\n",http_session.s_port,html_ses[i].d_port);
                if(http_session.s_port == html_ses[i].d_port){
                    
                    j=i;
                }
                else {
                    j=-1;
                    continue;
                }
                
                for(int k=0;k<4;k++){
                    if(http_session.IP_source[k] != html_ses[i].IP_destination[k]){
                       // printf("%d %d\n",http_session.IP_source[k],html_ses[i].IP_destination[k]);
                        j=-1;
                        break;
                    }
                }
                if(j==-1) continue;
                
                for(int k=0;k<4;k++){
                    if(http_session.IP_destination[k] != html_ses[i].IP_source[k]){
                      //  printf("%d %d\n",http_session.IP_destination[k],html_ses[i].IP_source[k]);
                        j=-1;
                        break;
                    }
                }
                if(j!=-1) break;
            }
           
            if(j!=-1){
                

                    int pos = http_session.prev_seq - html_ses[j].first_seqNum;
                    
                    fseek(ses_fp,pos,SEEK_SET);
                   
                    //write to file
                    if(html_ses[j].chunked==0){
                    r = strstr(ptr,"\r\n\r\n");
                    if(r!=NULL){
                   
                    html_ses[j].chunked=1;
                    
                    for(int i=r-ptr;i<(len-pd);i++){
                        
                            fprintf(ses_fp,"%c",ptr[i]);
                        
                    }
                    }

                    }
                    else{
                        
                        for(int i=0;i<(len-pd);i++){
                        
                            
                            fprintf(ses_fp,"%c",ptr[i]);
                        
                    }
                    
                    }
                    

                
            }
        
    }
    }
    }
   
    
}

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
            f=1;
            if(flag == 1){
                k = track[i].syn;
                k++;
                track[i].syn = k;
                
                
            }
            else{
                k = track[i].syn_ack;
                k++;
                track[i].syn_ack = k;
               
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
            {
                track[track_bound].syn=1;
                track[track_bound].syn_ack=0;
                
            }
            else
            {
                track[track_bound].syn_ack=1;
                track[track_bound].syn=0;
            }
           
        }
    

}
void check_flood(){
    
    for(int i=0;i<=track_bound;i++){
        if((track[i].syn-track[i].syn_ack)>20)
            spoof[++spoof_bound] = i;
           
    }
}


int pcap_Analysis(char fileName[100])
{
    struct GlobalHeader ghead;
    struct PacketHeader phead;
    struct EthernetHeader ehead;
    struct IP ip;
    struct TCP T;
    struct UDP U;
    struct http_ses http_session;
    mkdir("http_htmls", 0777);
    chmod("http_htmls",S_IRWXO);
    unsigned char c, protocol;
    unsigned short g;
    char flg[6];
    int pd=0,contains_pay=1;

    int add_skip=0;
    pf= fopen(fileName,"rb");
    fp =fopen("log.txt","w+");
    ff =fopen("Stas.txt","w+");

    fread(&ghead, sizeof(struct GlobalHeader), 1, pf);

    fprintf(fp,"Magic number: %x\n",ghead.magicNumber);
    fprintf(fp,"Version: %x.%x\n",ghead.versionMajor, ghead.versionMinor);
    fprintf(fp,"Time: %x\n",ghead.time);
    fprintf(fp,"Sigfig: %x\n",ghead.sigfigs);
    fprintf(fp,"snaplen: %x\n",ghead.snaplen);
    fprintf(fp,"network: %x\n",ghead.network);

    printf("Running.....\n");
    sleep(1.5);
    printf("Analysing packets\n");
    sleep(1);

    for(int it=0; !feof(pf); it++)
    {
        add_skip=0;
        pd=0,contains_pay=1;
        
        fprintf(fp,"\n\npack#%d\n\n: ",it+1);
        fread(&phead, sizeof(struct PacketHeader), 1, pf);

        fprintf(fp,"Length of packet: %d\n",phead.ocLen);

        fread(&ehead, sizeof(struct EthernetHeader), 1, pf);
        add_skip+=14;
        ehead.ethType= ntohs(ehead.ethType);

        fprintf(fp,"--------Ethernet Header-------\n");
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
        fprintf(fp,"Ethernet type: %x\n\n",ehead.ethType);

        if(ehead.ethType==2054){
            struct ARP arp;
            fprintf(fp,"ARP\n");
            fread(&arp, sizeof(struct ARP),1,pf);

            if(arp.hardware_type==256)
            fprintf(fp,"Hardware Type : Ethernet");
            fprintf(fp,"Protocol type : %d\n",arp.protocol);
            fprintf(fp,"Hardware size : %d\n",arp.hardware_size);
            fprintf(fp,"Protocol size : %x\n",arp.protocol_size);
            if(arp.opcode==256)
            fprintf(fp,"Opcode : Request\n");
            else if(arp.opcode==512)
            fprintf(fp,"Opcode : Response\n");

            fprintf(fp,"Sender MAC Address:");
            for(int i=0; i<6; i++)
            {
            fprintf(fp,"%02x",arp.sender_MAC[i]);
            if(i!=5)fprintf(fp,":");
            else fprintf(fp,"\n");
            }

            fprintf(fp,"Sender IP Address:");
            for(int i=0; i<4; i++)
            {
            fprintf(fp,"%d",(int)arp.sender_IP[i]);
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n\n");
             }

            fprintf(fp,"Target MAC Address:");
            for(int i=0; i<6; i++)
            {
            fprintf(fp,"%02x",arp.target_MAC[i]);
            if(i!=5)fprintf(fp,":");
            else fprintf(fp,"\n");
            }

            fprintf(fp,"Target IP Address:");
            for(int i=0; i<4; i++)
            {
            fprintf(fp,"%d",(int)arp.target_IP[i]);
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n\n");
            }

            
            continue;

        }

        else if(ehead.ethType==2048){
        fprintf(fp,"--------IP Header-------\n");
        fread(&ip, sizeof(struct IP),1,pf);
        add_skip+=20;
        unsigned short p,len;
        p=ip.IHL >>4;
        len=(ip.IHL & 0x0f);
        fprintf(fp,"IP Version Number: %d\n",(int)p);
        fprintf(fp,"IP header length is %d\n",(int)len*4);
        fprintf(fp,"Type of Service : %d\n",(unsigned int)ip.tos);
        fprintf(fp,"Total Length : %d\n",ntohs(ip.length));
        fprintf(fp,"Identification Number : 0x%x\n",(ntohs)(ip.id));
        fprintf(fp,"Time to live : %d\n",(unsigned int)ip.ttl);
        fprintf(fp,"Protocol : %d\n",ip.protocol);
        fprintf(fp,"Checksum : 0x%x\n",(ntohs)(ip.checksum));

        protocol = ip.protocol;


        fprintf(fp,"source IP:");

        int arr[4],arr2[4];
        int lm=0;
        
        for(int i=0; i<4; i++)
        {
            fprintf(fp,"%d",(int)ip.source[i]);
            //printf("%d\n",(int)ip.source[i]);
            arr[lm++]=(int)ip.source[i];
          //  printf("%d ",arr[lm-1]);
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n");
        }
       // printf("\n");
        lm=0;
        fprintf(fp,"destination IP:");
        for(int i=0; i<4; i++)
        {
            fprintf(fp,"%d",(int)ip.destination[i]);
            arr2[lm++]=(int)ip.destination[i];
            //printf("%d ",arr2[lm-1]);
            if(i!=3) fprintf(fp,".");
            else fprintf(fp,"\n\n");
        }
      //  printf("\n");
        int i=0;
        len=len*4;
        pd=phead.ocLen-(ntohs(ip.length)+14);
        
        //len=len-20;
        int skip = len-20;
        while(skip>0){
            add_skip++;
            fgetc(pf);
            skip--;
        }
        char ch;
        if(protocol==6)
        {
            fprintf(fp,"--------TCP Header-------\n");
            tcp++;
            //fprintf(fp,"this is TCP protocol\n");
            fread(&T,sizeof(struct TCP),1,pf);
            add_skip+=20;
            fprintf(fp,"SOURCE PORT: %d\n",ntohs(T.srcport));
            fprintf(fp,"DESTINATION PORT : %d\n",ntohs(T.destport));
            unsigned short hl = (T.tcp_resoff & 0xf0)>>4; 

                if((ntohs(ip.length)-(len+(hl*4)))==0){
                    contains_pay = 0;
                }
                skip = (hl*4)-20;
                
                while(skip>0){
                add_skip++;
                fgetc(pf);
                skip--;
                }
               

            if(ntohs(T.srcport==443 )|| ntohs(T.destport)==443){
                fprintf(fp,"This is a SSL packet\n");
            }
            
            else if(ntohs(T.srcport)==80 || ntohs(T.destport)==80){
                fprintf(fp,"This is a HTTP packet\n");
                http_session.prev_seq = ntohl(T.seqNum);
                http_session.prev_ack = ntohl(T.ackNUm);
                http_session.d_port = ntohs(T.destport);
                http_session.s_port = ntohs(T.srcport);
                for(int i=0;i<4;i++){
                http_session.IP_source[i] = ip.source[i];
                http_session.IP_destination[i]= ip.destination[i]; 
                }
                http_session.chunked=1;
                
                
                
                
            }
                
            

            fprintf(fp,"SEQUENCE NUMBER : %" PRIu32, ntohl(T.seqNum));
            fprintf(fp,"\n");

            fprintf(fp,"ACKNOWLEDGEMENT NUMBER: %" PRIu32, ntohl(T.ackNUm));
            fprintf(fp,"\n");

            
            fprintf(fp,"Header Length: %d\n", hl*4);


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


            
        }
        fprintf(fp,"Window Size : %d\n",ntohs(T.tcp_win));
        fprintf(fp,"Checksum : 0x%x\n",ntohs(T.tcp_checksum));
        fprintf(fp,"Urgent Pointer : %d\n\n",ntohs(T.tcp_urgptr));

        }

        else if(protocol==17)
        {
            udp++;
            fprintf(fp,"--------UDP Header-------\n");
            fread(&U, sizeof(struct UDP), 1, pf);
            add_skip+=8;
            fprintf(fp,"SOURCE PORT: %d\n",ntohs(U.srcport));
            fprintf(fp,"DESTINATION PORT : %d\n",ntohs(U.destport));
            fprintf(fp,"UDP length: %d\n",ntohs(U.len));
            fprintf(fp,"Checksum : 0x%x\n",ntohs(U.udp_checksum));

            // for(int i=0; i<12; i++)
            //     c= fgetc(pf);
        }

        else
        {
            if(protocol==0)fprintf(fp,"This is HOPOPT protocol");
            else if(protocol==1){
                fprintf(fp,"This is ICMP protocol");
                icmp++;
            }
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
            // for(int i=0; i<20; i++)
            //     c= fgetc(pf);
        }
        
        // printf("pack %d\n",it+1);
         
        // printf("%d\n",contains_pay);
         
         if(ntohs(T.srcport)==80 || ntohs(T.destport)==80){
              http_pay(phead.ocLen-add_skip,1,http_session,pd,contains_pay);
              T.srcport=0;
              T.destport=0;
         }
         else
        http_pay(phead.ocLen-add_skip,0,http_session,pd,contains_pay);
        // for(int bb=0; bb<(phead.ocLen-add_skip); bb++){
        //     c=fgetc(pf);
        //     printf("%02x ",(unsigned int)c);
        // }
        //     printf("\n");
            
        }

            else{
                //printf("he\n");
               for(int bb=0; bb<phead.ocLen-14; bb++)
                c=fgetc(pf);
            }
            add_skip=0; 
            }
        
            

    

    fprintf(ff,"TCP : %lld\nUDP : %lld\nICMP : %lld\n\n",tcp,udp,icmp);
    check_flood();
    fprintf(ff,"No.of IP addresses which probably has been flooded with SYN packets : %lld\n\n",spoof_bound+1);
    if(spoof_bound>=0){

        fprintf(ff,"IP ADDRESSES :");
    }
    
    for(int i=0;i<=spoof_bound;i++){
        for(int j=0;j<4;j++){
            if(j!=3)fprintf(ff,"%d.",track[i].IP[j]);
            else fprintf(ff,"%d",track[i].IP[j]);
        }
         fprintf(ff,"(Number of received SYN packets is %ld && Number of sent SYN_ACKs is %ld)\n",track[i].syn,track[i].syn_ack);
        
    }

    

    printf("\n\nDONE!\n");

    return 0;



}