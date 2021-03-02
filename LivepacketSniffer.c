#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "Headers.h"
#include "colors.h"

#define ETHER_LEN 6

FILE *pf, *part, *fp;
int c = 0, httpN = 0, tcpN = 0, udpN = 0, sslN = 0, icmpN = 0;
char FileName[1000];
int keepRunning = 1;
int packetNo = 0;
char ssl_inf[500];
char vers[20];

void printStatistics()
{
    print(White);
    printf("Details saved in file packetLog.txt\n");
    printf("--------SUMMARY--------\n");
    printf("Total no. of\n\nTCP packets : %d\nUDP packets : %d\nHTTP packets : %d\nSSL packets : %d\n", tcpN, udpN, httpN, sslN);
    refresh();
}

void intHandler(int dummy)
{
    printf("\033[5m\033[1m\033[3m\033[%dm", Red);
    printf("Terminating...\n");
    refresh();
    sleep(1);
    keepRunning = 0;
    printStatistics();
}
unsigned char st[10];
void fill_info(int t, unsigned char *p)
{
    int i;
    for (i = 0; i < t; i++)
    {
        st[i] = (unsigned char)p[i];
    }
    st[i] = '\0';
}
int isHTTP(unsigned char *pay, int size)
{
    unsigned char c = (unsigned char)pay[0];
    unsigned char c1 = (unsigned char)pay[1];
    unsigned char c2 = (unsigned char)pay[2];

    if (c == 'H' && c1 == 'T' && c2 == 'T')
    {

        fill_info(9, pay);

        return 1;
    }
    if (c == 'G' && c1 == 'E' && c2 == 'T')
    {
        fill_info(3, pay);
        return 2;
    }
    if (c == 'P' && c1 == 'O' && c2 == 'S')
    {
        fill_info(4, pay);
        return 3;
    }

    if (c == 'H' && c1 == 'E' && c2 == 'A')
    {
        fill_info(4, pay);
        return 4;
    }

    if (c == 'D' && c1 == 'E' && c2 == 'L')
    {
        fill_info(6, pay);
        return 5;
    }
    return 0;
}

void printPayload(unsigned char *pay, int len)
{

    for (int i = 0; i < len; i++)
    {

        if (i != 0 && i % 16 == 0)
        {
            fprintf(pf, "        ");

            for (int j = i - 16; j < i; j++)
            {

                if (pay[j] >= 32 && pay[j] <= 128)
                {
                    fprintf(pf, "%c", (unsigned char)pay[j]);
                }
                else
                    fprintf(pf, ".");
            }
            fprintf(pf, "\n");
        }

        if (i % 16 == 0)
            fprintf(pf, " ");
        fprintf(pf, "%02x", (unsigned int)pay[i]);

        if (i == len - 1)
        {
            for (int j = 0; j < 15 - i % 16; j++)
            {
                fprintf(pf, "   ");
            }
            fprintf(pf, "       ");

            for (int j = i - i % 16; j <= i; j++)
            {
                if (pay[j] >= 32 && pay[j] <= 128)
                {
                    fprintf(pf, "%c", (unsigned char)pay[j]);
                }
                else
                {
                    fprintf(pf, ".");
                }
            }

            fprintf(pf, "\n\n");
        }
    }
}

int getSSLinfo(unsigned char *p, int len)
{

    if (len < 5)
        return 0;
    struct sslheader *SSL = (struct sslheader *)p;
    int record_protocol = (unsigned int)SSL->record_type;
    int ver1 = (unsigned int)SSL->ver1, ver2 = (unsigned int)SSL->ver2;

    if (record_protocol == 20)
    {
        fprintf(pf, "-------SSL Packet-------\n");
        fprintf(pf, "Record Type : ");
        fprintf(pf, "Change Cipher Spec ");
        strcpy(ssl_inf, "Change Cipher Spec ");
    }

    else if (record_protocol == 21)
    {
        fprintf(pf, "-------SSL Packet-------\n");
        fprintf(pf, "Record Type : ");
        fprintf(pf, "Alert");
        strcpy(ssl_inf, "Alert ");
    }

    else if (record_protocol == 22)
    {
        fprintf(pf, "-------SSL Packet-------\n");
        fprintf(pf, "Record Type : ");
        fprintf(pf, "Handshake ");
        strcpy(ssl_inf, "Handshake ");
    }
    else if (record_protocol == 23)
    {
        fprintf(pf, "-------SSL Packet-------\n");
        fprintf(pf, "Record Type : ");
        fprintf(pf, "Application Data");
        strcpy(ssl_inf, "Application Data ");
    }

    else
    {
        return 0;
    }
    fprintf(pf, "\nVersion : ");
    strcat(ssl_inf, " ");
    //version
    if (ver1 == 3 && ver2 == 0)
    {
        fprintf(pf, "SSL 3.0");
        strcat(vers, "SSL 3.0");
    }

    else if (ver1 == 3 && ver2 == 1)
    {
        fprintf(pf, "TLS 1.1");
        strcat(vers, "TLS 1.1");
    }

    else if (ver1 == 3 && ver2 == 2)
    {
        fprintf(pf, "TLS 1.2");
        strcat(vers, "TLS 1.2");
    }

    else if (ver1 == 3 && ver2 == 3)
    {
        fprintf(pf, "TLS 1.3");
        strcat(vers, "TLS 1.3");
    }
    fprintf(pf, "\nLength : ");

    fprintf(pf, "%d\n", ntohs(SSL->len1) + (unsigned int)(SSL->len2));
    return 1;
}

void processPackets(unsigned char *buffer, int length)
{

    packetNo++;
    int color;
    fprintf(pf, "PACK# %d\n", packetNo);
    struct iphdr *ip = (struct iphdr *)buffer;
    struct sockaddr_in IPsource, IPdest;

    memset(&IPsource, 0, sizeof(IPsource));
    memset(&IPdest, 0, sizeof(IPdest));

    IPsource.sin_addr.s_addr = ip->saddr;
    IPdest.sin_addr.s_addr = ip->daddr;
    unsigned int ver = (unsigned int)ip->version;
    unsigned int iphdrlen = (unsigned int)ip->ihl * 4;
    unsigned int protocol = (unsigned int)ip->protocol;

    fprintf(pf, "-------IP HEADER-------\n");
    fprintf(pf, "Source IP : %s\n", inet_ntoa(IPsource.sin_addr));
    fprintf(pf, "Destination IP : %s\n", inet_ntoa(IPdest.sin_addr));
    fprintf(pf, "IP Version : %d\n", ver);
    fprintf(pf, "IP Header Length : %d\n", iphdrlen);
    fprintf(pf, "Protocol : %d\n", protocol);
    fprintf(pf, "Type of Service : %d\n", (unsigned int)ip->tos);
    fprintf(pf, "Checksum : %d\n", ntohs(ip->check));
    fprintf(pf, "Identification : %d\n", ntohs(ip->id));
    fprintf(pf, "TTL : %d\n\n", (unsigned int)ip->ttl);

    if (protocol == 6)
    {
        tcpN++;
        color = Yellow;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen);
        unsigned int tcphdrlen = (unsigned int)(tcp->doff * 4);
        fprintf(pf, "-------TCP HEADER-------\n");
        fprintf(pf, "Source Port : %d\n", ntohs(tcp->source));
        fprintf(pf, "Destination Port : %d\n", ntohs(tcp->dest));
        fprintf(pf, "Sequence NUmber : %u\n", ntohl(tcp->seq));
        fprintf(pf, "TCP header Length : %d\n", tcphdrlen);
        fprintf(pf, "TCP flags:\n");
        fprintf(pf, "URG : %d\n", (unsigned int)tcp->urg);
        fprintf(pf, "ACK : %d\n", (unsigned int)tcp->ack);
        fprintf(pf, "PSH : %d\n", (unsigned int)tcp->psh);
        fprintf(pf, "RST : %d\n", (unsigned int)tcp->rst);
        fprintf(pf, "SYN : %d\n", (unsigned int)tcp->syn);
        fprintf(pf, "FIN : %d\n", (unsigned int)tcp->fin);
        fprintf(pf, "Window Size : %d\n", ntohs(tcp->window));
        fprintf(pf, "Checksum : %d\n", ntohs(tcp->check));
        fprintf(pf, "Urgent Pointer : %d\n\n", (unsigned int)tcp->urg_ptr);

        char tm[20] = "TCP";
        int fl = 0;

        refresh();

        unsigned short payload_len = length - (iphdrlen + tcphdrlen);

        if ((ntohs(tcp->source) == 80 || ntohs(tcp->dest) == 80) && (isHTTP(buffer + iphdrlen + tcphdrlen, payload_len)))
        {

            httpN++;

            color = Blue;
            snprintf(FileName, 1000, "file%d.html", c++);
            fprintf(pf, "\n\n\n");
            fl = 1;
            print(color);
            strcpy(tm, "HTTP");
            printf("%-20s", inet_ntoa(IPsource.sin_addr));
            printf("%-20s%-20s%-20d%-20d %s\n\n", inet_ntoa(IPdest.sin_addr), tm, ntohs(tcp->source), ntohs(tcp->dest), st);
            fl = 1;
        }

        else if ((ntohs(tcp->source) == 443 || ntohs(tcp->dest) == 443) && (getSSLinfo(buffer + iphdrlen + tcphdrlen, payload_len)))
        {

            color = Cyan;
            sslN++;
            print(color);
            char temp[] = "Length : ";
            printf("%-20s", inet_ntoa(IPsource.sin_addr));
            printf("%-20s%-20s%-20d%-20d%-20s\n\n", inet_ntoa(IPdest.sin_addr), vers, ntohs(tcp->source), ntohs(tcp->dest), ssl_inf);
            vers[0] = '\0';
            refresh();
            fl = 1;
        }

        if (fl == 0)
        {
            print(color);
            char temp[] = "SYN :";
            printf("%-20s", inet_ntoa(IPsource.sin_addr));
            printf("%-20s%-20s%-20d%-20d%s %d ACK : %d\n\n", inet_ntoa(IPdest.sin_addr), tm, ntohs(tcp->source), ntohs(tcp->dest), temp, tcp->syn, tcp->ack);
            refresh();
        }
        fprintf(pf, "\n-------THE PAYLOAD--------\n");
        printPayload(buffer + iphdrlen + tcphdrlen, payload_len);
        fprintf(pf, "\n\n\n");
    }

    if (protocol == 17)
    {

        color = Magenta;
        struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen);

        unsigned short payload_len = length - (iphdrlen + ntohs(udp->len));

        fprintf(pf, "-------TCP HEADER-------\n");
        fprintf(pf, "Source Port : %d\n", ntohs(udp->source));
        fprintf(pf, "Destination Port : %d\n", ntohs(udp->dest));
        fprintf(pf, "Length : %d\n", ntohs(udp->len));
        fprintf(pf, "Checksum : %d\n", ntohs(udp->check));
        fprintf(pf, "\n-------THE PAYLOAD--------\n");

        printPayload(buffer + iphdrlen + ntohs(udp->len), payload_len);
        fprintf(pf, "\n\n\n");
        print(color);
        char temp[] = "UDP";
        char temp2[] = "Length : ";
        printf("%-20s", inet_ntoa(IPsource.sin_addr));
        printf("%-20s%-20s%-20d%-20d%s%d\n\n", inet_ntoa(IPdest.sin_addr), temp, ntohs(udp->source), ntohs(udp->dest), temp2, ntohs(udp->len));
        refresh();
    }

    if (protocol == 1)
        icmpN++;
    sleep(1);
}

int Livepktcap()
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    struct sockaddr saddr;
    int addrlen, data;

    if (sockfd < 0)
    {
        printf("Failed to create socket\n");
    }
    printf("\033[5m\033[1m\033[3m\033[%dm", Green);
    printf("Starting....\n\n\n");
    refresh();

    pf = fopen("packetLog.txt", "w+");
    signal(SIGINT, intHandler);
    unsigned char *buffer = (unsigned char *)malloc(65536);
    int p = 30;
    char tm[] = "IP Source Address";
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    refresh();

    strcpy(tm, "IP Dest Address");
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    refresh();

    strcpy(tm, "Protocol");
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    refresh();

    strcpy(tm, "Source Port");
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    refresh();

    strcpy(tm, "Dest Port");
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s", tm);
    refresh();

    strcpy(tm, "Info");
    printf("\033[1m\033[3m\033[%dm\033[%dm", p, White + 10);
    printf("%-20s\n", tm);
    refresh();
    printf("\n");

    while (keepRunning)
    {

        addrlen = sizeof(struct sockaddr);
        data = recvfrom(sockfd, buffer, 65536, 0, &saddr, &addrlen);
        if (data < 0)
        {

            printf("Receive failed\n");
            return 1;
        }

        processPackets(buffer, data);
    }

    close(sockfd);
}