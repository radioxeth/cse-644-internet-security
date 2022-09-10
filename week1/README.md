# Week 1 Introduction to Internet Security

## 1.5 Packet Flow Over the Internet

## 1.8 IP Address

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