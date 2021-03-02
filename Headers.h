#ifndef HEADERS_INCLUDED
#define HEADERS_INCLUDED


struct iphdr {
	u_int32_t ihl:4,version:4;	
	u_int8_t  tos;		
	u_int16_t tot_len;		
	u_int16_t id;		
	u_int16_t frag_off;		
	u_int8_t  ttl;		
	u_int8_t  protocol;			
	u_int16_t check;		
	u_int32_t saddr;
    u_int32_t daddr;
};

struct tcphdr{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t skip:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t skip2:2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};


struct Echo{
    u_int16_t        id;
    u_int16_t        sequence;
};
struct Fragment{
      u_int16_t        unused;
      u_int16_t        mtu;
    
};

union unanymoous{
    struct Echo echo;
    struct Fragment frag;                       
  };

struct icmphdr
{
  u_int8_t type;                
  u_int8_t code;                
  u_int16_t checksum;
  union unanymoous un;
};
 
struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};


struct GlobalHeader
{
    u_int32_t       magicNumber;
    u_int16_t versionMajor;
    u_int16_t versionMinor;
    u_int32_t                time;
    u_int32_t      sigfigs;
    u_int32_t       snaplen;
    u_int32_t      network;
};

struct PacketHeader
{
    u_int32_t tSec;
    u_int32_t tuSec;
    u_int32_t ocLen;
    u_int32_t packLen;
};


struct EthernetHeader
{
    u_char      destination[6];
    u_char     source[6];
    u_int16_t ethType;
};

struct ARP{
    u_int16_t hardware_type;
    u_int16_t protocol;
    u_char hardware_size;
    u_char protocol_size;
    u_int16_t opcode;
    u_char  sender_MAC[6];
    u_char  sender_IP[4];
    u_char  target_MAC[6];
    u_char  target_IP[4];

};


struct sslheader{
    u_char record_type;
    u_char ver1,ver2;
    u_int16_t len1:8,len2:8;
    
};


#endif