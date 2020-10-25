#ifndef HOSTNAMETOIP_INCLUDED
#define HOSTNAMETOIP_INCLUDED

int convertHosttoIp(char  hostname[],char* ip,struct sockaddr_in *destAddr);
int IPtoHostName(char *ip,char * hostName) ;

#endif

