

int convertHosttoIp(char  hostname[],char* ip,struct sockaddr_in *destAddr){

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
    (*destAddr).sin_family=host->h_addrtype;
    (*destAddr).sin_port=htons(0);
    (*destAddr).sin_addr.s_addr=*(long*)host->h_addr;
    return 1;
}


int IPtoHostName(char *ip,char * hostName) 
{ 
    struct sockaddr_in ipAddr;   
    memset(&ipAddr,0,sizeof(struct sockaddr_in));
    char host[NI_MAXHOST];

    ipAddr.sin_family=AF_INET;
    ipAddr.sin_port=htons(0);
    inet_pton(AF_INET,ip,&ipAddr.sin_addr);

   
  
    if (getnameinfo((struct sockaddr *) &ipAddr,sizeof(struct sockaddr_in),host,sizeof(host), NULL, 0, NI_NAMEREQD))  
    { 
        return 0;
    } 

    strcpy(hostName,host);
    return 1;
    
} 


