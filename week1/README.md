# Week 1 Introduction to Internet Security

## Directory
- [Home](/README.md#table-of-contents)
- **&rarr;[Week 1 Introduction to Internet Security](/week1/README.md#Week-1-Introduction-to-Internet-Security)**
- [Week 2 Sniffing and Spoofing Packets](/week2/README.md#Week-2-Sniffing-and-Spoofing-Packets)


## 1.5 Packet Flow Over the Internet
([top](#directory))

## 1.8 IP Address
([top](#directory))

*classful scheme*
32-bit ip address $2^{32}$

- Class A
  - $2^{24}$
- Class B
  - $2^{16}$
  - 128.230.0.0/**16**-netid
  - 128.230.0.0/**14**
- Class C
  - $2^8$

Routing is based on netid
Net mask to identify where the boundary is from netid to hostid

IPv6 and NAT (netword adjust translation)

## 1.9 Data link layer ethernet
([top](#directory))

payload Hardware addreess (MAC) burned into the NIC (permanent address)

## 1.10 ARP Protoco
([top](#directory))
l
- Address Resolution Protocol

IP $\Leftarrow$ $\Rightarrow$ Mac


Names->DNS->IP

**Broadcast** $\Rightarrow$ **Unicast**

ARP Cache Poisoning

## Live Session
([top](#directory))

Do not follow due dates with syllabus.

Collaborate with others on slack

To spoof, put victim pc to sleep through DOS attack
Once the victim is asleep, force the address to 