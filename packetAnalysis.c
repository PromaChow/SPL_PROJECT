#include<stdio.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h>
#include"LearnToAnalyzePcap.c"
#include"LivepacketSniffer.c"
#include"port_Scanning.c"
#include"ping1.c"
#include"regx.h"
#include"HostNameToIp.h"

int main(int argc,char * argv[]){

    if(argc<2){
        printf("Very Few Arguments\n");
        return 0;
    }
    char parse[11];

    if(argv[1][0]=='-'){
        int i;
        for( i=1;argv[1][i]!='\0';i++){
            parse[i-1]=argv[1][i];

        }
        parse[i-1]='\0';
       // printf("%s",parse);

        if(strcmp(parse,"pcap")==0){
            
            if(argc>2){
                //printf("%s",argv[2]);
                pcap_Analysis(argv[2]);
            }
            else{
                printf("Too few arguments\n");
                return 0;
            }
        }
    
    else if(strcmp(parse,"livepktcap")==0){
        printf("%s",parse);
        Livepktcap();
    }

    else if(strcmp(parse,"port")==0){
        if(argc<3)
        printf("Too few arguments\n");

        else{
            if(argc == 3){
                port_scan(argv[2],'0',-1,-1);
            }

            else{
                if(strcmp(argv[2],"-r")==0 || (strcmp(argv[2],"-s"))==0){
                    if(argv[2][1] == 's'){
                        port_scan(argv[3],'s',atoi(argv[4]),-1);
                    }
                    else{
                        port_scan(argv[3],'r',atoi(argv[4]),atoi(argv[5]));
                    }
                }
                else{
                    printf("E : Incorrect Format\n");
                }
            }
        }
       
    }

    else if(strcmp(parse,"ping")==0){

        if(argc==3){
        sendPing(-1,argv[2]);
        }
        else{
            sendPing(atoi(argv[2]),argv[3]);
        }
    }
    }
    

}