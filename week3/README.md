# Week 3 IP Protocol

## Directory
- [Home](/README.md#table-of-contents)
- [Week 2 Sniffing and Spoofing Packets](/week2/README.md#Week-2-Sniffing-and-Spoofing-Packets)
- **&rarr;[Week 3 IP Protocol](/week3/README.md#Week-3-IP-Protocol)**
- [Week 4 Firewall](/week4/README.md#Week-4-Firewall)

## 3.2 IP Protocol
([top](#directory))

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
([top](#directory))

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
([top](#directory))

> **protocol** *In information technology, a protocol is the special set of rules that end points in a telecommunication connection use when the communicate. Protocols speci*fy interactions between the communicating entities.*

- Attackers are people who don't follow the rules

**Attacker Strategry**
- do not follow the rule
- create unreal condition

## 3.5 Attacks on IP Fragmentation
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

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
([top](#directory))

- IP Protocol
- IP Fragmentation
- Attacks on IP fragmentation
- ICMP protocol
- Attacks on ICMP protocol
- Routing

## Live Session
([top](#directory))

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
