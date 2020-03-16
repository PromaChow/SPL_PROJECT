#include<stdio.h>
#include<string.h>

unsigned short csum(unsigned short *ptr,int size) 
{
	unsigned long int sum;
	unsigned short oddbyte;
	unsigned short int answer;

	sum=0;
	while(size>1)
    {
		sum+=*ptr++;
		size-=2;
	}
	if(size==1)
    {
		oddbyte=0;
		*((unsigned char*) & oddbyte)=*(unsigned char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0x0000ffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return answer;
}