
# Week 6 DNS

## Directory
- [Home](/README.md#table-of-contents)
- [Week 5 TCP Protocol](/week5/README.md#Week-5-TCP-Protocol)
- **&rarr;[Week 6 DNS](/week6/README.md#Week-6-DNS)**
- [Week 7 Secret Key Encryption and One-way Hash Function](/week7/README.md#Week-7-Secret-Key-Encryption-and-One-way-Hash-Function)

## 6.2 Domain Name Systems (DNS)
([top](#directory))

- humans want to go to nammed address
- computer only knows IP address
- we need something in the middle,
  - something the translate name to address and vice-versa

### Where do we start?
- many computers involved in DNS
- centralized approach...
  - does not scale well
  - primary target
- distributed solution
  - many computer
  - each computer knows part of the names out there
  - how do I find them?
  - use a structure

## 6.3 Organization of DNS Domains
([top](#directory))

### Organization of DNS Zones
- apollo.syr.edu
  - IP (ns = named server)
    - ns.syr.edu 128.230.12.7
    - ns1.syr.edu 128.230.12.8
    - ns2.syr.edu 128.230.12.9
- how do we get there?

### Heirarcical structure
- ROOT
  -Top Level Domain (TLD)
    - com
      - apple.com
      - microsoft.com
    - net
    - edu
      - syr.edu
    - mil
    - org
    - etc
  - Country-code TLD
    - .fr
    - .cn
    - .uk
    - .br
  - Custom TLD
    - .bank
    - .hotel

### DNS Zone vs Domain
- Domain
  - 
- Zone

### Root Zone File
- https://www.internic.net/domain/root.zone
  - each root hosts this informatoin

## 6.4 Exercise: DNS Query
([top](#directory))

### DNS Query: Principle
- send query to local DNS server
  - dns cache
  - ask root
  - /etc/hosts
    - static mapping
    - name<->ip
- global dns server
  - google public DNC
  - 8.8.8.8
  - 8.8.4.4
    - consequence of privacy
    - free DNS server wants to know where you go, what your behaviors are

### DNS Iterative Query
- local dns server
  - receives query from user, **www.example.net**
  - sends query to root server
    - no I don't know the answer
    - I know somebody else who might know the answer
    - ask **.net** server
    - I don't know the answer
      - ask **example.net**
        - www might be in example.net
  - cache the answer
    - cache will expire

<img src="//images/daniel_shannon_dns_query.png"/>

## 6.5 Set Up Your Own DNS
([top](#directory))

### What happens when you have bought a domain name?
example.com
- vendor
  - go daddy
- Get IP address block
- name server
  - connect to hierarchy
- root
  - com
    - need to register name server and ip address
    - example.com


### Set up your own DNS Server

> /etc/bind/named.conf (BIND configuration file)
```bash
zone "example.net"{
  type master;
  file "/etc/bind/example.net.db";
};

zone "0.168.192.in-addr.arpa"{
  type master;
  file "/etc/bind/192.168.0.db";
}
```

> zone file
```
$TTL 3D ; default expiration time of all resource records without their own TTL

@ IN SOA ns.example.net. admin.example.net.(
  1 ; Serial
  8H; Refresh
  2H; Retry
  4W; Expire
  1D); Minimum
@ IN NS ns.example.net; address of name server
@ IN MX 10 mail.example.net/ ; Primary Mail Exhanger

www  IN A 192.168.0.101; address of www.example.net
mail IN A 192.168.0.102; address of mail.example.net
ns   IN A 192.168.0.10 ; address of ns.example.net
*.example.net. IN A 192.168.0.100; address for other url in the example.net domain
)
```


## 6.6 Reverse DNS Lookup
([top](#directory))

### Reverse DNS Lookup
IP->name
- similar to forward lookup

- find name for 128.320.171.184
  - construct a name as a string
  - "184.171.230.128 **.in-addr** **.arpa** **.**"
  - . (root)
    - .arpa
      - .in-addr (name server)
### Reverse Lookup Zone File
### Question: Using Domain Name as the Basis for Access Control
- **do not use domain name as the basis for access control**
- SU -> Server
  - src IP
    - Server does reverse lookup
    - syr.edu

## 6.7 Attack Surface
([top](#directory))

### Attack Surface
- denial of service on the internet
- dns cache poisoning
  - spoof the dns cache server

## 6.8 Fake Data Attacks
([top](#directory))

### fake data in the additional section
- rule
  - discard urelated information in addtional section

### face data in the authority section
- rule
  - out of zone... drop
  

## 6.9 DNS Cache-Poisoning Attack
([top](#directory))

- local DNS server
  - send request to server
  - attack injects reply
    - give them the fake IP

- DNS request is UDP 
  - what is a valid response?
    - src IP
    - dest IP
    - src port (53 dns query)
    - dest port (assigned by OS)
    - transaction ID (16 bit)
      - match response with request
  - local dns server will store response
    - response sets the cache period

## 6.11 Remote DNS Cache-Poisoning Attack
([top](#directory))

- The challenges
  - need to guess
    - dest port #: ?
    - transaction ID: ?
  - cache effect slows down progress

### Kaminsky attack
hints
  1. don't ask for the domain you want to poison
  2. two addtional fields
     - authority 
     - additional

You can request using a random named server and set the authority to ns.attacker.com

### Counter Measures
- use enryption to preserve integrity
- dificulty in deployment!
  - have to change the whole internet

#### DNSSEC

## 6.12 Construct DNS Packets for Attacks
([top](#directory))

- How do you spoof the DNS reply?
- in order to construct the DNS response
  - construct IP header
  - construct UDP header
    - data: DNS record, DNS has its own header
      - Transaction ID
        - `0x8400`
          - dns response
          - authoritative answer
      - number of Question Records (1)
      - number of Answer Records (1)
      - number of Authority Records (1)
      - number of Additional Records (0)

### DNS Response Payload
- question record
  - name
    - ns.example.com
  - record type
    - "A" record `0x0001`
  - class
    - internet `0x001`
- answer record
  - name
  - record type
    - A record
    - `0x001`
  - class
  - time to live (cache)
  - data length
  - data: ip address
- authority record
  - name
  - record type
    - NS record
    - `0x002`
  - class
  - time to live (cache)
  - data length
  - data: name server

### Construct DNS Reply

```C
unsigned short construct_dns_reply(char *buffer){
  struct dnsheader *dns = (struct dnsheader *) buffer;

  //construct the dns header
  dns->flags=htons(0x8400);//flag = response this is a dns response

  // the number of certain fields
  dns->QDCOUNT=htons(1); //1 the question field
  dns->ANCOUNT=htons(1); //1 answer field
  dns->NSCOUNT=htons(1); //1 name server (authority) field
  dns->ARCOUNT=htons(1); //1 additional field

  char *p=buffer+12;// move the pointer to the beginning of the DNS data

  if(strstr(p, TARGET_DOMAIN)==NULL) return 0; // only target one specific domain

  p += strlen(p) +1 +2+2;// skip the question section (no change)

  p += set_A_record(p, NULL, 0x0C, ANSWER_IPADDR); // add an A record (Answer Section)
  p += set_NS_record(p, TARGET_DOMAIN, 0, NS_SERVER); // add an NS record (Authority Section)
  p += set_A_record(p, NS_SERVER, 0, NS_IPADDR); // add an A record (additional section)

  return p-buffer;
}
```

### Construct an "A" record

```C
unsigned short set_A_record(char *buffer, char *name, char offset, char *ip_addr){
  char *p=buffer;

  if(name==NULL){
    *p = 0xC0; p++;
    *p = offset; p++;
  }else{
    strcpy(p,name);
    p+=strlen(name)+1;
  }

  *((unsigned short *)p)=htons(0x001);//record type
  p+=2;
  *((unsigned short *)p)=htons(0x001);//class
  p+=2;
  *((unsigned short *)p)=htonl(0x00002000);//time to live
  p+=4;
  *((unsigned short *)p)=htonl(0x0004);//data length
  p+=2;
  *((struct in_addr *)p)->s_addr=inet_addr(ip_addr);//IP Address
  p+=4;

  return (p-buffer);
}
```

## 6.14 Denial-of-Service attack on DNS Server
([top](#directory))

- DOS attacks on the **root servers**
  - root is very robust and hard to take down
  - need many resources
- DOS attacks on the **.cn nameservers**

## 6.14 Summary
([top](#directory))

- DNS Structure, root servers, TLDs
- how DNS works
- set up DNS servers
- attack surface
- attacks on DNS
  - fake data attacks
  - dns cache poinsoning & kaminsky attack
  - how to construct DNS-response
  - case studies: Denial-of-service

# Week 8 Live Session: Web Security
([top](#directory))
