
## 10.2 BGP and Attacks on BGP

```bash
$ traceroute
```

## 10.3 How the Internet is Connected

### How the internets is connected: high-level picture

- each network is an Autonomous System (AS)
  - AS#
- networks are connected by a cable
  - Exchange
  - Peering point
- software
  - BGP
    - Border Gateway Protocol 
    - tell connecting network what addresses are on your network
    - routing protocol

- SU AS# 11872
- cogent (national)
- nysernet (regional)
- ineternet2 (national)

## 10.4 How Backbones are Connected Physically

Physcially lay the cable

### Internet Exchange and Peering

### Manhattan Landing Exchange Point
- secured facility
- can cut physical cables

### Network Tiers

- Peering/exchange
  - price?

- Tier 1
  - large networks
  - international networks
  - sprint, AT&T
    - no transit
    - direct connection
- Tier 2
  - Purchase transit service from tier 1
- Tier 3
  - Purchase transit service from tier 2

## 10.5 Disputes Related to Peering and Connections

### Level 3 vs Cogent Dispute (2005)

## 10.6 How Networks are "Glued" Together

### How BGP Works

- SU network
  - AS 11872
- Cogent
  - AS 174

- SU and Cogent are connected physically
  - SU tells Cogent what network they own
    - 128.230.0.0
    - BGP Speaker

  - 128.230.0.0/16
    - go to 11872 (AS path)
  - 128.230.0.0/16
    - go to 174 through 11872
    - and so on

- many paths!
  - some are avoided
  - some are prefered


### BGP Update

### Find BGP-Related Information

```bash
$ whois -h whois.radb.net 128.230.32.13

route:      128.230.32.0/19
origin:     AS11872
descr:      Proxy registration for Syracuse University
admin-c:    William Owens
tech-c:     NYSERNet NOC
remarks:    This is a proxy registration by NYSERNet on behalf of one of our member campuses. For changes or removal, contact noc@nysernet.org
notify:     noc@nysernet.org
notify:     rmbunal@syr.edu
mnt-by:     MAINT-AS3754
changed:    owens@nysernet.org 20190807
source:     RADB

person:     NYSERNet NOC
address:    100 South Salina St
            Suite 300
            Syracuse, NY 13202
phone:      315-415-8508
e-mail:     noc@nysernet.org
nic-hdl:    ZN56-ARIN
notify:     noc@nysernet.org
mnt-by:     MAINT-AS3754
changed:    owens@nysernet.org 20190826  #20:36:07Z
source:     RADB
```


## 10.7 BGP Prefix Deaggregation and Applications

Rule: longest match!

- two regions
  - SU        
    - 128.230.0.0/16 AS# 11872
  - SU London
    - 128.230.5.0/24 AS# 11872

- Want to send ip packet to 128.230.5.6,
  - choose longest match, 128.230.5.0/24

## 10.8 IP Anycast

### IP Anycast F-Root Server

IP Address 192.5.5.241
ASN AS3557 (internet systems consortium)

Many different locations, 30+

- BGP select one to set the router
  - h

## 10.9 Attacks on BGP

### How to attack a network using BGP

SU anounces 128.230.0.0/16
- Cogent
- nysernet
- BGP speakers make tcp connection
  - TCP RST attack will break BGP connection
  - Denial of Service
- Attacker owns AS
  - Has a BGP speaker
  - anounce they are connected to SU network
    - damange, some traffic routed to attacker AS
  - have the longest IP deaggregation!
    - all traffic will go to attacker AS


## 10.10 Case Studies on Attacks

### Pakistan Hijacks YouTube

Wanted to block citizens from watching youtube.

YouTube
  - 208.65.152.0/22
Pakistan
  - 208.65.153.0/24

#### Response to Attack

- fake 208.65.153.0/24
- announce a more specific IP route!
  - 208.65.153.0/32

### Turkey Hijacks Global DNS Providers

- turkey wants to censor twitter.com
- Turk Telekom DNS
  - provide fake IP for twitter
- there are other DNS providers
  - GOVt hijacked 
    - 8.8.8.8
    - 208.67.222.222
    - 4.2.2.2
  - as9121 announce
    - 8.8.8.8/32
    - 208.67.222.222/32
    - 4.2.2.2/32
  - Supposed to announce it to the inside of turkey network
  - announced it to the whole world lol

### Syria Turned off its internet
- AS9121 turk telecom
- AS3491 PCCW global


## 10.11 Protecting BGP

### Protecting BPG

- Encryption
  - deaggregation is an issue
  - SGPB
    - secure BGP

## 10.12 Summary

- How the internet is connected
- Internet exchange and peering
- Network tiers and disputes
- BGP and how it works
- BGP prefix deaggregation and IP anycast
- Attacks on BGP and case studies
