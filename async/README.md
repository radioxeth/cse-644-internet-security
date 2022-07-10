# Week 1 Introduction to Internet Security

## 1.5 Packet Flow Over the Internet

## 1.8 IP Address

*classful scheme*
32-bit ip address $2^32$

- Class A
  - $2^24$
- Class B
  - $2^16$
  - 128.230.0.0/**16**-netid
  - 128.230.0.0/**14**
- Class C
  - $2^8$

Routing is based on netid
Net mask to identify where the boundary is from netid to hostid

IPv6 and NAT (netword adjust translation)

## 1.9 Data link layer ethernet

payload Hardware addreess (MAC) burned into the NIC (permanent address)

## 1.10 ARP Protocol
- Address Resolution Protocol

IP $\Leftarrow$ $\Rightarrow$ Mac


Names->DNS->IP

**Broadcast** $\Rightarrow$ **Unicast**

ARP Cache Poisoning

## Live Session
Do not follow due dates with syllabus.

Collaborate with others on slack

To spoof, put victim pc to sleep through DOS attack
Once the victim is asleep, force the address to 

# Week 2 Sniffing and Spoofing Packets

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
  if(ip-iph_protocol == IPPROTO_ICMP){
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