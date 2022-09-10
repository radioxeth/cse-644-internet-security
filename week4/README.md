
# Week 4 Firewall

## Directory
- [Home](/README.md#table-of-contents)
- [Week 3 IP Protocol](/week3/README.md#Week-3-IP-Protocol)
- **&rarr;[Week 4 Firewall](/week4/README.md#Week-4-Firewall)**
- [Week 5 TCP Protocol](/week5/README.md#Week-5-TCP-Protocol)

## 4.2 Firewall
([top](#directory))

- write a firewall
- use a firewall
- attackers bypass firewalls

## 4.2 Overview of How Firewall Works
([top](#directory))

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
([top](#directory))

- lots of diagrams

## 4.4 Linux Firewall Implementation
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

- concepts of firewall
- firewall implementation (simple packet filter)
- netfilter and iptables
- evading firewall using SSH tunnel
- Web proxy firewall

## 4.9 UDP and Attacks
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

- Transport layer
- port number
 - UDP protocol and header
 - UDP applications
 - Attacking strategy: magnify power, ping-pong
 - Attack on or using UDP


# Week 5 Live Session
([top](#directory))

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
