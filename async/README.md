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


# Week 3 IP Protocol

## 3.2 IP Protocol

IP Header and Protocol (32-bits)
- 4-bit version (4)
- 4-bit header length
  - multiply by 4
- 8-bit Type of service
  - TOS
  -Router uses a priority queue, determined by TOS?
    - doesn't work well for the internet.
    - works well for a centralized company or organization
- 16-bit total length
  - header+payload 2^16



**Fragmentation**
- 16-bit identification (ID)
- 3-bit flags
- 13-bit fragmentations offset

**TTL**
- 8-bit TTL (time to live)
  - number of router hops
- 8-bit protocol
  - TCP,UDP,something else
- 16-bit checksum

**32-bit source ip address**
**32-bit destination ip address**

### How Traceroute Works

A$\rightarrow$B number of hops? Use TTL

1. send first packet
   - ttl = 1
   a. first router
      - ttl = 0
      - drop, send message back
2. send second packet
   - ttl = 2
   b. gets to second router
      - ttl = 0
      - drop, send message back
3. and so on


## 3.3 IP Fragmentation
- complicated, so attacker finds opourtunity

### IP Fragmentation: Why

$2^{16}=65536$ (64k)

The wire doesn't accomidate a packet of 64k, 1500 limit on frames usually, standard
- MTU: maximum transmit unit
  - depends on the wire

**Sender**
- Each fragmentation of the original packet is turned into separate IP Packets
- Fragments may not take the same route
  - put together at the end

**Receiver**
- put packets into buffer
- if one packet is dropped, the entire packet is dropped

|400|400|400|
|-|-|-|

- whole packet (16-bit ID)
  - packet 1:
    - ID
    - offset: $0/2^3$*
    - bit-flag: 1
  - packet 2:
    - ID
    - offset: $400/2^3$
    - bit-flag: 1
  - packet 3:
    - ID
    - offset: $800/2^3$
    - bit-flag: 0 (last packet)

*divide offset by 2^3 because the total length is 16-bit and the fragmentation offset is 13-bit

**3-bit offset**

0. not used
1. don't fragment
2. more fragments

## 3.4 Attacks on IP Fragmentation

> **protocol** *In information technology, a protocol is the special set of rules that end points in a telecommunication connection use when the communicate. Protocols speci*fy interactions between the communicating entities.*

- Attackers are people who don't follow the rules

**Attacker Strategry**
- do not follow the rule
- create unreal condition

## 3.5 Attacks on IP Fragmentation

### Attack 1: Tie Up Target's Resources

> Can you use a small amount of bandwidth to tie up a target machine's significant amount of resources.

Send a single packet with offset of $2^{16}$ and say it is the last packet, server will allocate 65k. Send many small packets with large offest to tie up resources.

### Attack 2: Create a super-large packet

> Can you create an IP packet that is larget thank 65536 bytes?

### Attack 3: Create Abnormal Situation

> Can you create some abnormal condition using offset and payload size?

Create overlapping packet fragments.

Don't assume that packets comming in order have the right offest.

## 3.6 ICMP Protocol

### ICMP: Internet Control Message Protocol

**Purpose**
- Control message
- Error message

### ICMP Header

|ICMP Type|Type Code|ICMP Checksum|
|-|-|-|

ICMP Echo Request/Reply

|ICMP Type|Type Code|ICMP Checksum|
|-|-|-|
|0 or 8|Code (0)|Checksum|

data: echo reply (type 0) myst return any data sent in echo request

### ICMP Time Exceeded
**Type** must be set to 11
**Code** specifies the reason for the first time exceeded message, including the following:
|Code|Description|
|-|-|
|0|time to live exceeded in transit|
|1|Fragment reassembly time exceeded|

### ICMP Destination Unreachable
|ICMP Type|Type Code|ICMP Checksum|
|-|-|-|
|3|Code|Checksum|
|||

|code|description|
|-|-|
|0|Destination network unreachable|
|1|Destination host unreachable|
|2|Destination protocol unreachable|
|3|Destination port unreachable|
|4|Fragmentation required and DF flag set|
|5|Source route failed|
|6|Destination netwrok unknown|
|7|Destination host unknown|
|8|Source host isolated|
|9|Network administratively prohibited|
|10|Host administratively prohibited|
|11|Network unreachable for TOS|
|12|Host unreachable for TOS|
|13|Communication administrativel prohibited|
|14|Host precedence violation|

## 3.7 Attacks on ICMP

### ICMP Redirect and Attacks

#### protocol
Two routers on network
host sends out information that goes through r1 or r2.
Host has a routing table, help host decide which direction to go
r1 and r2 both have routing tables
if r1 has 4 hops compared to 5 hops for r2, host will choose r1.
if now r2 is shorter, 3 hops, then r2 will send ICMP redirect to host and update the routing table.

#### attacker
redirect host to x
x could be a malicious router, launch a man in the middle attacker
x could be a black hole, machine that doesn't exist

### Smurf Attack
**Doesn't work anymore*

Magnify the power.
Directed broadcast

Send out a packet using the direct boradcast IP. 128.230.5.0/24

128.230.5.255 (directed broadcast), everyone will see it, directed broadcast will send N packets to everyone, but these N packets will be returned to you, attacking yourself.

If we spoof the vicitim's IP, send to broadcast, N packets will be returned to victim.

**Why doesn't this work anymore?**

## 3.8 Routing

**Routing:**
1. routing tables
2. routing decision

|To reach network|Route to this address|
|-|-|
|20.0.0.0/8|Deliver Direct|
|30.0.0.0/8|Deliver Direct|
|10.0.0.0/8|20.0.0.5|
|40.0.0.0/8|30.0.0.7|


## 3.9 Routing Table

line 1 is default route, destination 0.0.0.0
router is connected to 0.0.0.0 and that is the gateway IP address

### Change the routing table

`$ sudo route add -net 128.230.0.0/16 gw 10.0.2.1`

### How do routers and host get routing information?

*External Routing* (BGP`)
Every network has a representative and figure out which destinations you can reach.
They will talk to all of the other networks (not directly)

*Interior Routing*
Then routing protocols happen inside the network

## 3.10 Summary

- IP Protocol
- IP Fragmentation
- Attacks on IP fragmentation
- ICMP protocol
- Attacks on ICMP protocol
- Routing

## Live Session

### Firewalls
### Introduction
- seen evolution of information systems
- now everyone wants to be on the internet
  - and to interconnect networks

### What is a Firewall?
- a choke point of control and monitoring
- interconnects networks with different trust
- impose restrictions on network services
  - only authorized traffic is allowed
- auditing and controlling access
  - can implement alarms for abnormal behavior
- provide NAT (network address translation) & usage monitoring
- implement VPNs using IPsec
- must be immune to penetration

### Firewall Limitations
- cannot protect from attacks bypassing it
  - eg sneaker net, utility modems, trusted organizations, trusted services (SSL SSH)
- cannot protect against internal threats
- connat protect against internal trheats
- cannot protect against acces via WLAN
  - if improperly secured against external use
- Cannot protect against malware imported via laptop, PDS, storage infected outside

### Firewall - packet filters
- simplest firewall component
- foundation of any firewall system
- examine each IP packet (no context) and permit or deny according to rules
- hence restrict access to services (ports)

### Attacks on packet filter
- ip address spoofing
- source routing attacks
- tiny fragment attacks

### Stateful packet filters
in the transport layer
- traditional packet filters do not examine higher layer context
  - ie matching return packets with outgoing flow
- stateful packet filters address this need
- they examine each IP packet in context
  - keep track of client-server sessions
  - check each packet validity belongs to one
- hence are better able to detect bogus packet out of context
- may even inspect limited application data
  - what data?

### Application level gateway (proxy)
application lyaer
- have application specific gateway/proxy
- has full access to protocol
  - user requests srevice from proxy
  - proxy validates request as legal
  - then actions request and returns packet

### Firewalls - circuit level gateway
- realys two TCP connections
- imposes security by limiting which such connections are allowed

### Bastion Host
- highly secure host system
  - web servers should be like this
  - can open up entire network to attacks if not careful.
- runs circuit/application level gateways

### Host-based firewalls
- often used on servers
- can tailor filtering rules to host environemtn

### Personal Firewalls


# Week 4 Firewall

## 4.2 Firewall

- write a firewall
- use a firewall
- attackers bypass firewalls

## 4.2 Overview of How Firewall Works
- firewall inspects packets
- based on policy
  - accept
  - deny
  - modify (redirect?)
- looks at packets in both diretions
  - ingress (coming into network)
  - egress (leaving network)

### types of firewall
#### look at ip layer of packet
- packet filter (stateless)
- stateful firewall
  - look at multiple packets together
  - let packet go out if it belongs to existing connection
  - uses more resources
#### look at data layer of packet
- application firewall
  - (web proxy)
## 4.3 Overview of how Firewall Works
- lots of diagrams

## 4.4 Linux Firewall Implementation
- nees to understand how packets flow into the host

- packet flows into system's NIC
- NIC goes to router, two options
  - not for me, so route to another NIC
    - if computer is not a router, drop the packet
    - can set up computer to forward packets
  - packet is for me, send to local process
    - enter system
    - need to find a place to put the firewall and filter packets
      1. before routing
      2. after routing, before send to local/process
      3. after local process, before routing
      4. after local routing before NIC
    - this is done inside kernel
      1. change kernel
         - have to recompile the kernel
      2. Loadable kernel module
         - use prebuilt kernel
         - write the kernel in the user space
      - have to have a place to put the code
      - _net filter_
        - creates hooks in kernel.
        - did anyone connect to this hook?
          - if so, filter
          - else, do nothing
### Netfilter: Implement a simple firewall

#### Hooking filter code to one of the netfilter hooks

- filter out telnet (port 23)
  - if 23 drop packet
```C
static struct nf_hook_ops telnetFilterHook;

int setUpFilter(void){
  printk(KERN_INFO "Regisering a telnet filter.\n");
  telnetFilterHook.hook = telnetFilter; // defined in next code section
  telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
  telnetFilterHook.pf = PF_INET;
  telnetFilterHook.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&telnetFilterHook);
  return 0;
}

void removeFilter(void){
  printk(KERN_INFO "Telnet filter is being removed.\n");
  nf_unregister_hook(&telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);
```

#### implementation of the filter

```C
unsigned int telnetFilter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
  struct iphdr = *iph;
  struct tcphdr = *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)) { // if packet is TCP && port 23
    printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
    ((unsigned char *)&iph->daddr)[0],
    ((unsigned char *)&iph->daddr)[1],
    ((unsigned char *)&iph->daddr)[2],
    ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  }else{
    return NF_ACCEPT;
  }
}
```

## 4.5 Exercise: Iptables and UFW

### iptables and uncomplicated firewall (UFW)

- ip tables
  1. firewall implementation
  2. user level program
     - confgiure what is inside kernel
  - contains the rules
  - use netfilter
- several tables
  - filter
    - filtering
  - NAT table
    - network address translation
    - modification of packet src/dest addr
  - magle
    - modify many things in packet
- check connectioin and implement stateful policy
  - powerful

### using UFS to set up firewall rules
- front end of IP tables

`ufw <action> <direction> <service>`
...
`ufw (allow | deny) (in | out) from (src) to (dest) port (port number)`
1. > Prevent client machine from telnetting to any external machine
   - `sudo ufw deny out from ${CLIENT_IP} to any port 23`
2. > Prevent client machine from access a website
   - `sudo ufw deny out from ${CLIENT_IP} to ${DEST_IP} port 80`

## 4.6 Exercise: Bypassing Firewall Using SSH Tunnel
- set up a counter measure
- firewalls can be too restrictive so people want to bypass the firewall

### Bypassing Firewalls
- inside network, we can connect to server
- firewall prevents outside from connecting to server
- if I'm travelling, I cannot connect to server

- we want to set up a *proxy* inside the network, and we can create a tunnle to the proxy
  - the tunnel will be encrypted

- tunnel
  1. VPN
     - IP layer
  2. SSH
     - Transport layer
  3. HTTP 
     - Application layer

### SSH Tunnel: Static Port Forwarding
- ingress
  - Client (application) (:8000) tunnels to Proxy(:22), bypassing firewall
  - Proxy (:22) makes request to server (:23) inside network
  - telnet localhost 8000
  `ssh -L 8000:server:23 proxy`
- egress
  `ssh -L 23:client:8000 proxy`

### SSH Tunnel: Dynamic Port Forwarding
`ssh -D 9000 -c proxy`


## 4.7 Web Proxy

### Web Proxy: Application Firewall
- proxy server
  - drop packet
  - redirect

### Web Proxy: Squid
- Firewall
- URL rewrite and redirect
- web caching

```perl
#!/usr/bin/perl -w

use strict;
use warnings;

select STDOUT; $| = 1;

while(<>){
  my @parts = split;
  my $url = $parts[0];

  if($url =~ /\.(jpg|bmp|gif|jpeg)/){
    print "http://mars.syr.edu/html/seed/stopsign.png\n";
  }else{
    print "\n";
  }
}

```

## 4.8 Summary

- concepts of firewall
- firewall implementation (simple packet filter)
- netfilter and iptables
- evading firewall using SSH tunnel
- Web proxy firewall

## 4.9 UDP and Attacks
## UDP Overview

### Transport Layer and Port Numbers
- We need IP address to send packets from A to B.
- But which application on the server needs the packet?
  - this is the port number

#### Port Number
- Transport Layer Address

Layers
1. 
2. Ethernet Address
3. Network Layer (IP Address)
4. Transport Layer (port number)

Port Numbers
- 16 bit, $2^{16}$, 0-65535
- port conventions
  - 0-1023
    - well known applcations (root privilege)
      - telnet :23
      - ssh :22
      - http :80
      - https :44
  - 1024-49151
    - register port
  - 49152-65535
    - dynamic & private ports
    - when we send a packet, the OS assigns a return/src port address.
  
## 4.11 UDP Header and Protocol
- Transport Layer
  - TCP
    - complicated header
    - no packet loss
    - organize out of order packets
  - UDP
    - light layer on top of the IP layer
      - Source Port Number
      - Destination Port Number
      - (UDP length; standard on all layers)
      - (UDP checksum; standard on all layers)
    - Best effort delivery
      - Packet Loss
    - IP Doesn't care which order the packets come in. 
    - UDP only adds port number, same responsibilities as IP

### UDP Client/Server Programs
#### UDP client
a. create socket
   - `sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);`
   - `SOCK_DGRAM` data gram
b. send data
   - `sendto(sockfd, buffer,...,struct sockaddr *)&servaddr, ...);`
c. receive data
   - `recvfrom(sockfd, rec_buffer, ..., &from_addr, ...);`

#### UDP server
a. create socket
   - `sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`
b. bind the socket to a port
   - `bind(sockfd, &si_me, ...)`
c. receive data
   - `recvfrom(sockfd, rec_buffer, ..., &from_addr, ...)`

## 4.12 Exercise: UDP Applications

- DNS protocol
- video/audio streaming
  - realtime
    - UDP
    - packet loss doesn't matter too much
  - recorded
    - tcp
- real-time applications

UDP
- light weight
- packet loss



### Question

> UDP does not preserve order and does not handle packet loss. If an application does care about packet loss and order, can it still use UDP?
- Yes
  - if packet loss occurs, send request to client to resend dropped packets

## 4.13 Attacks on UDP

### Causing Great Damange Using a Grenade
- attack wants to target a powerful server
- minimize cost

> How to magnify power?
  - grenade
  - want to cause a lot damange with a small tool
  1. Turn one grenade into many
     - SMURF attack using ICMP
     - 
  2. Turn one grenade into missile
  3. Achilles Heel
     - find the weak point

#### UDP attack
- Attacker sends a small packet to a server that returns a large packet
- Attacker uses the victim's IP as the src IP instead of their own.

### Target Achilles Heel: UDP Ping-Pong
- attacker `echo :7`
- victim replies to src ip
- attacker sets src ip to dest ip, and sets src and dest port to 7. This will infinitely reply lol.

## 4.14 Summary
- Transport layer
- port number
 - UDP protocol and header
 - UDP applications
 - Attacking strategy: magnify power, ping-pong
 - Attack on or using UDP


# Week 5 Live Session
### TCP IP Vulnerabilites
TCP/IP Vulnerabilities
- transmissioncontrol protocol/internet protocol
- unauthorized users may launch a denial-of-service attack on the destination computer

### Data Encapsulation
- Data encapsulation
  - enclosing higher-level protocol information in lower level protocol information
  - also called data hiding
  - implementation details of a class are hidden from user

### IP Internet Protocol
- Internet Protocol
  - transmits data from source to final destination
  - network protocol operating at layer 3 of the OSI model
    - and layer 2or 3 of the TCP/IP model
  - IP is connectionless
  
- 2 verions of IP
  - IPv4 (32-bit address)
  - IPv6 (128-bit)
    - writeen as group of 8 hex addresses

- fragmentations
  - does kernel or user fragment packets?

#### TCP 
- souce and destination computer exchange the **initial sequence number** (ISN)

# Week 5: TCP Protocol

## 5.2 The TCP Protocol and Attacks on TCP

### The need for TCP

- UDP does not:
  - packet loss
  - preserve order

- TCP:
  - handle packet loss
  - preserves order

## 5.3 TCP Client/Server Programming

### TCP Client Program
```C
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int main(){
  //Create socket
  int sockfd = socket(AF_INET,SOCK_STREAM,0);
  
  //Set the destination information
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(struct sockaddr_in));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_add = inet_addr("10.0.2.17");
  dest.sin_port = htons(9090); // host to network (short, port is a short)

  // connect to the server
  connect(sockfd, (struct sockaddr *)&dest, sizeof(struct sockaddr_in)); // establish connection!
  //

  //write data
  char *buffer1 = "Hello server\n";
  char *buffer2 = "Hello again!\n";
  write(sockfd, buffer1, strlen(buffer1));
  write(sockfd, buffer2, strlen(buffer2));

  return 0;
}
```

- UDP is a data gram
- TCP is a stream

### TCP Server Program
```C
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int main(){
  int sockfd, newsockfd,
  struct sockaddr_in my addr, client_addr;
  char buffer[100];

  //create socket
  sockfd = socket(AF_INET,SOCK_STREAM,0);

  // set the destination information
  memset(&my_add,0,sizeof(struct sockaddr_in));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(9090);

  //bind the socket to a port number
  bind(sockfd. (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)); //register with port
  //(client side OS dynamically assigns port)

  //listen for connections
  listen(sockfd, 5); // i am ready - this is a queue, application get stuff out of queue
  int client_len = sizeof(client_addr);
  newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);// block, wait, dequeue

  // read data
  memset(buffre, 0, sizeof(buffer));
  int len = read(newsockfd, buffer, 100);
  printf("received %d bytes: %s", len, buffer);

  return 0;
}
```

### Accepting multiple connections
```C
while (1) {
  newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
  if (fork()==0){//child process
    close(sockfd);
    //read data
    memset(buffer, 0, sizeof(buffer));
    int len = read(newsockfd, buffer, 100);
    printf("received  %d bytes. \n%s\n", len, buffer);

    close(newsockfd);
    return 0;
  } else { // parent process
    close(newsockfd);
  }

}
```
- after you `accept`
  - fork to create a new process
  - create a new socket
- old socket needs to be used to wait for data