#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>


int convertHosttoIp(char  hostname[],char ip[]){

    struct hostent *host;
    //char   *ptr;
    struct in_addr **address;

    host=gethostbyname(hostname);
    if(host == NULL)
    {
        printf("Error retrieving IP from hostname");
        return 0;
    }
    address = (struct in_addr **) host->h_addr_list;

    //  for(int i = 0; address[i] != NULL; i++)
    // {  
    //     strcpy(ip ,inet_ntoa(*address[i]) );
    //     return 0;
    // }

    strcpy(ip,inet_ntoa(*address[0]));
    return 1;
}
