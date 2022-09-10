# Week 2 Sniffing and Spoofing Packets

## Directory
- [Home](/README.md#table-of-contents)
- [Week 1 Introduction to Internet Security](/week1/README.md#Week-1-Introduction-to-Internet-Security)
- **&rarr;[Week 2 Sniffing and Spoofing Packets](/week2/README.md#Week-2-Sniffing-and-Spoofing-Packets)**
- [Week 3 IP Protocol](/week3/README.md#Week-3-IP-Protocol)

## 2.2 Sniffing and Spoofing
## 2.3 Packet Sniffing

- promiscuous mode 
  - NIC
- wifi (uses channels)
  - monitor mode
  - use different channels to communicate
    - if you don't listen the right channel, you won't hear anything

### how to snif

- wireshark
#### diy

- turn on promiscuous mode
- socket: raw socket

``` C
//Creation of the socket
sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
//setting up the device into promiscuous mode and binding the socket to the device
struct packet_mreq mr;

mr.mr_type = PACKET_MR_PROMISC;
setsockopt(sock_fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr));

//setup the BPF packet filter

setsockopt(sock_fd, SOL_SOCKET,SO_ATTACH_FILTER, &bpfcode, sizeof(bpfcode));

//capturing data from the socket

while(1){
  recvfrom(soc_fd,buffer,65536,0,&saddr,&saddr_size);
}
```

#### capture packets using PCAP API

```C
int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  //char filter_exp[]="port 23";
  char filter_exp="";
  bpf_u_int32 net;

  //open live pcap session on nic with name eth0
  handle = pcap_open_live("eth18",BUFSIZ,1,1000,errbuf);

  //compile filter_exp into BP psuedo-code
  pcap_compile(handle, &fp, filter_exp,0,net);

  pcap_setfilter(handle,&fp); //setup BPF code on the socket
  pcap_loop(handle,-1,got_packet,NULL); // capture packets -- SEE BELOW FOR got_packet
  pcap_close(handle); //close the handle
  return 0;
}
```

#### get a packet and process it

```C
void got_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *packet){
  struct ethheader *eth = (struct ethheader *)packet;
  if(eth->header_type !=ntohs(0x0800)) return;//not an ip packet

  struct ipheader* ip=(struct ipheader*)(packet + SIZE_ETHERNET);
  int ip_header_len = ip->iph_ihl*4;

  printf("----------------------"\n);
  // print souce and destination ip address
  printf("    From: %s\n",inet_ntoa(ip->iph_sourceip));
  printf("      To: %s\n",inet_ntoa(ip->iph_sourceip));

  // determine protocol
  if(ip->iph_protocol == IPPROTO_ICMP){
    printf("    Protocol: ICMP\n");
    spoof_icmp_reply(ip);
  }
}

```

## 2.4 Packet Spoofing


#### packet sending

```C
int main()
{
  // create socket
  int sockfd = socket(AF_INET,SOCK_DGRAM,0);

  //set the destination information
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(struct sockaddr_in));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr("10.0.2.5");
  dest.sin_port = htons(9090);

  // send data
  char *buffer = "Hello Server!\n";
  sendto(sockfd, buffer, strlen(buffer),0,(struct sockaddr *)&dest,sizeof(dest));
  close (sockfd);
  return 0;
}
```

- system uses normal socket, provides sender ip and udp addresses
- use raw packet to spoof

```C
void send_raw_ip_packet(struct ipheader* ip){
  struct sockaddr_in dest_info;
  int enable = 1;
  
  // create a raw network socket and set its options
  int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

  // provide needed information about destination
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // send the packet out
  printf("sending spoofed IP packet... \n");
  sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info,sizeof(dest_info));
  close(sock);
}
```

## 2.5 Constructing Raw Packets


```C
// IP Header
struct ipheader{
  unsigned char       iph_ihl:4, iph_ver:4; //IP header length and version
  unsigned char       iph_tos; //type of service
  unsigned short int  iph_len; // ip packet length both (data and header)
  unsigned short int  iph_indent; //identification
  unsigned short int  iph_flag:3,iph_offset:13; //flags and fragmentation offset
  unsigned char       iph_ttl; //time to leave
  unsigned char       iph_protocol; // type of upper-level protocol
  unsigned short int  iph_chksum; // ip datagram checksum
  struct in_addr      iph_sourceip; // ip source address (in network byte order)
  struct in_addr      iph_destip;   //ip destination address (in network byte order)
}

char buffer[LENGTH];
struct ipheader *ip = (struct ipheader*) buffer;
struct udpheader *udp = (struct udpheader*) (buffer + sizeof(struct ipheader));
char *data = buffer + sizeof(struct ipheader) + sizeof(stuct udpheader);
```

## 2.6 Spoofing Packets

### Spoofing ICMP Packet
```C
/*********************
Spoof an ICMP echo request using an arbitrary source IP address
*********************/

int main(){
  char buffer[PACKET_LEN];
  
  memset(buffer, 0, PACKET_LEN);

  /**************************
  Step 1: fill in the ICMP header.
  **************************/
  struct icmpheader *icmp=(struct icmpheader *)(buffer + siezof(struct ipheader));
  icmp->icmp_type=8; //ICMP type: 8 is request, 0 is reply

  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_chksum((unsigned short *)icmp, sizeof(struct icmpheader));

  /*************************
  Step 2: fill in the IP header
  *************************/
  struct ipheader *ip = (struct ipheader *) buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
  ip->iph_destip.s_addr = inet_addr(DEST_IP);
  ip->iph_protocol = IPPROTO_ICMP; // the value is 1, representing ICMP
  ip->iph_len = htons(sizeof(struct ipheader)+sizeof(struct icmpheader));

  // no need to set the following fields, as they will be set the byt he system
  // ip->iph_chksum = ...

  /************************
  Step 3: Finally, send the spoofed packet
  ************************/
  send_raw_ip_packet (ip);

}
```

### Spoofing UDP Packet
```C
int main(){
  char buffer[PACKET_LEN];
  memset(buffer, 0, PACKET_LEN);
  struct ipheader *ip = (struct ipheader *) buffer;
  struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));

  /*************************************
  Step 1: Fill in the UDP data field
  *************************************/
  char *data = buffer + sizeof(struct ipheader)+sizeof(struct udpheader);
  const char *msg = "hello udp\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);

  /*************************************
  Step 2: Fill in the UDP header
  *************************************/
  udp->udp_sport = htons(SRC_PORT);
  udp->udp_dport = htons(DEST_PORT);
  udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  upd->upd_sum = 0; //many OSes ignore this field, so we will not calculate it.
}

```

## 2.7 Sniffing and Spoofing: Code and Examples

> **snoofing** *sniffing and spoofing*

### Snififng the ICMP requeset


[get a packet and process it](#get-a-packet-and-process-it)
```C
got_packet(...); //see above (get a packet and process it)

/****************************************
given a captured ICMP echo request packet, construct a spoofed ICMP
echo reply, which includes IP + ICMP (there is no data)
****************************************/
void spoof_icmp_reply(struct ipheader* ip){
  int ip_header_len = ip->iph_ipl * 4;
  const char buffer[BUFSIZE];

  struct icmpheader* icmp = (struct icmpheader *)((u_char *)ip + ip_header_len);
  if(icmp->icmp_type!=8) {//only process icmp recho request
    printf("not an echo request\n");
    return;
  }

  // make a copy from original packet to buffer (faked packet)
  memset((char*)buffer,0,BUFSIZE);
  memset((char*)buffer,ip,ntohs(ip->iph_len));
  struct ipheader * newip = (struct ipheader *) buffer;
  struct icmpheader * newicmp = (struct icmpheader *) ((u_char *)buffer + ip_header_len);

  // construct IP: sqap src and dest in faked ICMP packet
  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->source_ip;
  newip->iph_ttl = 20;
  newip->iphprotocol = IPPROTO_ICMP;

  // fill in all the needed ICMP header information
  // ICMP Type: 8 is request, 0 is reply
  newicmp->icmp_type = 0;

  // Calculate the checksum for integrity. ICMP checksum includes the data
  newicmp->icmp_chksum = 0; // set it to zero first
  newicmp->icmp_chksum = in_chksum((unsigned short *)newicmp,ntohs(ip->iph_len) - ip_header_len);

  send_raw_ip_packet(newip);
}
```

Three steps to the *snoofing* stack
1. Sniffing
2. Spoofing Copy info/construct packet
3. Send spoofed packet

## 2.8 Byte Order

When A sends integer to B
Say integer is `0x87654321`

order matters for different computer architectures. So we have to speficy the order of bytes `little endian` or `big endian` using the **network order** and **host order**

> **h** *host*

>**n** *network*

|macro|description|functionality|
|-|-|-|
|`htons()`|Host to Network Short|used to convert unsigned short integer from host byte-order to netowrk byte-order|
|`htonl()`|Host to Network Long|used to conver unsigned integer from host byte-order to network byte-order|
|`ntohs()`|Network to Host Short|used to conver unsigned short integer from network byte-order to host byte-order|
|`ntohl()`|Network to Host Long|used to convert unsigend integer from network byte-order to host byte-order|

## 2.9 Summary

- packet sniffing using `pcap library`
- packet spoofing using raw socket
- sniffing and spoofing
- byte order

## Week 3 Live Session

### IP Security
- VPN or SSL for ipsec
- Kerberos
  - Distributed computing authorization mechanism
  - username and password, authentication server, implementation server
- https is http over ssl
- These protocols are formed in different layers of the protocol stack
  - ipsec, ip layer
  - we do not see how the packets are formed when 

#### General IP security mechanism
- provides
  - authetication
  - confidentiality
  - key management
- VPN applicable to use over LANs, across public and private WANs, and for the internet
- need authentication, encryption in IPv4 & IPv6

TCP/IP was not developed with security features!

#### Benefits of IPSec
- in a firewall/router provides strong security to all traffic crossing the perimeter
- in a firewall/router is a resistant to bypass
- is below transport layer, hence **transparent to applications**
- can be **transparent to end users**
- can provide security for individual users
- secures reouting architecture

NAT (networ address transport) protocol

#### IP Security Architecture (very important)
If you are trying to modify IPSec, you need to work with these consortiums.
- specification is quite complex, with groups:
  - Architecture
    - RFC4301 *Security Architecture for Internet Protocol*
  - Authentication Header (AH)
    - RFC4302 *IP Authentication Header*
  - Encapsulating Security Payload (ESP)
    - RFC4303 *IP Encapsulation Security Payload (ESP)
  - Internet Key Exchange (IKE)
    - RFC4306 *Internet Key Exchange (IKEv2) Protocol*
  - Cryptographic Algorithms
  - Other

#### IPSec Services
- Access Control
- Connectionless integrity
- Data origin authentication
- Rejection of replayed packets
  - a form of partial sequence integrity
- Confidentiality (encryption)
- Limited traffic flow confidentiality

#### Transport and Tunnel Modes
- Transport Mode
  - To encrypt & optionally authenticate IP data
  - can do traffic analysis but is efficient
  - good for ESP host to host traffic
- Tunnel Mode
  - encrypts entire IP packet
  - add new header for next hop
  - no routers on way can examine inner IP header
  - good for VPNs, gateway to gateway security

Tunnel mode is good for VPN, transport mode is good for network traffic analysis

#### Security Associations
- a one-way relationship between sender and receiver that affords security for traffic flow
- defined by 3 parameters:
  - Security Parameters Index (SPI)
  - IP destination address
  - Security Protocol Identifier
- has a number of other parameters

