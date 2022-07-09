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