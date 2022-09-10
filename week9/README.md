
# Week 9 VPN

## Directory
- [Home](/README.md#table-of-contents)
- [Week 8 Public-Key Encryption and PKI](/week8/README.md#Week-8-Public-Key-Encryption-and-PKI)
- **&rarr;[Week 9 VPN](/week9/README.md#Week-9-VPN)**
- [Week 10 BGP](/week10/README.md#week-10-BGP)

## 9.2 Virtual Private Network

### Why VPN?

- private network
- firewall
  - internal network is trusted
  - less protections inside

- employee wants to access internal network
  - internet is unstrustworthy

- how do we make our computer looks like it's insise the private network?

**Tunneling Techniques**
**Transparent**

## 9.3 How VPN Works

### Solutions

- Computer **A** is traveling
- Private Network
  - want to be transparent to computer **A**
- Dedicated **VPN Server**
  - **A** requests tunnel with **VPN server**
  - **A** puts data in the tunnel
    - encrypted
    - integrity
- **VPN Server** extracts payload and delivers to destination in private network

### IP Tunneling

#### IPSec Approach
- kernel

#### SSL/TLS Approach
- user space
- better than IPSec
  - don't have to change kernel
  - is other OS compatible with kernel changes?

## 9.4 VPN Implementation 1

### The TUN/TAP Interface

- **A** telnet to **C** (in the private network) over the internet

- A to C
  - packet is redirected to VPN client
    - via socket, just send data, not whole IP packets
    - virtual NIC
    - standard TCP UDP encryption tunnel
  - (typically packet goes to NIC and is then routed)

- how does the VPN client get the IP Packet?
  - TUN/TAP interface

### Create a TUN Interface (Virtual Network Interface)

#### Code

``` C
int tunfd;
struct ifreq ifr;
memset(&ifr, 0, sizeof(ifr));

ifr.ifr_flags = IFF_TUN | IFF_NO_IP;

tunfd = open("/dev/net/tun", O_RDWR);//virtual interface
ioctl(tunfd, TUNSETIFF, &ifr);
```

#### Compile and run the code

```bash
seed@ubuntu(10.0.2.18):~/vpn/TunDemo$ gcc -o tundemo tundemo.c
seed@ubuntu(10.0.2.18):~/vpn/TunDemo$ ./tundemo
TUN file descriptor: 3
```

#### Check the interface

```bash
seed@ubuntu(10.0.2.18):~/vpn/TunDemo$ ifconfig tun0 //new nic
```

#### Assign an IP address to the tun0 interface

```bash
seed@ubuntu(10.0.2.18):~/vpn$ sudo ifconfig tun0 10.0.4.99/24 up //asign IP
seed@ubuntu(10.0.2.18):~/vpn$ ifconfig tun0
```

#### check the route for 10.0.4.0/24 network (the route is automatically added)

```bash
seed@ubuntu(10.0.2.18):~/vpn/$  route
```

#### if the route is not there, use the following command to add it

```bash
sudo route add -net 10.0.4.0/24 tun0
```

### Read From and Write to the TUN Interface

#### Read from the tun interface
```bash
.../TunDemo# xxd <& 3 //read file descriptor 3
ping 10.0.4.32
```

#### write to the tun interface

```bash
#cat file >& 3
```

## 9.5 VPN Implementation 2

- telnet generates IP TCP/UDP Data
- routing to tun interface
- TUN Program (client)
  - encryption
  - MAC (message authentication control)
  - encapsulated into new packet
  - new  IP header
  - new transport layer header
- tunnel
  - UDP
  - TCP
  - whatever transport protocol you want
- TUN Program (servers)
  - decryption
  - verify MAC
- Write to tun interface
- original payload available
- routing
- payload no longer protected once inside the network

- what is the source IP?
  - of the tunnel packet
  - use TUN program IP

## 9.6 VPN Code Explanation 1

### VPN Implementation Code: The Overall Flow

- Start
- Create TUN Interface
- Establish the tunnel with the other end (socket interface)
- Monitor both TUN and socket interfaces
  - TUN
    - Get data from TUN send it to the tuneel
  - Socket
    - Get data from tunnel, write to TUN interface

### Establish the Tunnel

#### VPN Client

```C
int connectToUDPServer{
  int sockfd;
  char *hello="Hello";
  
  memset(&peerAddr, 0, sizeof(peerAddr));
  peerAddr.sin_family = AF_INET;
  peerAddr.sin_port = htons(PORT_NUMBER);
  peerAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  // Send a hello message to "connect" wtih the VPN server
  sendto(sockfd, hello, strlen(hello), 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));

  return sockfd;
}
```

#### VPN Server

```C
int initUDPServer(){
  int sockfd;
  struct sockaddr_in server;
  char buff[100];

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(PORT_NUMBER);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  bind(sockfd, (struct sockaddr*) &server, sizeof(server));

  //wait for the VPN client to "connect"
  bzero(buff,100);
  int peerAddrLen = sizeof(struct sockaddr_in);
  int len = recvfrom(sockaddr, buff, 100, 0, (struct sockaddr*) &peerAddr, &peerAddrLen);

  printf("Connected with the client: %s\n", buff);
  return sockfd;

}
```

## 9.7 VPN Code Explanation 2

#### Monitor the TUN and Socket Interfaces

```C
// enter the main loop

while(1){
  int ret;
  fd_set readFDSet;

  FD_ZERO(&readFDset);
  SD_SET(sockfd, &readFDSet);
  FD_SET(tunfd, &readFDSet);
  ret = select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL); // block on select, create a SET of interfaces
  // this is a blocking process

  if(FD_ISSET(tunfd, &readFDSet))
    tunSelected(tunfd, sockfd);
  
  if(FD_ISSET(sockfd, &readFDSet))
    socketSelected(tunfd, sockfd);
}
```

- use block on interface!
  - instead of round robin,
  - don't want to waste resources

### Transfer Data Between TUN and Tunnel

#### From TUN to tunnel
```C
void tunSelected(int tunfd, int sockfd){
  int len;
  char buff[BUFF_SIZE];

  printf("got a packet from TUN\n");
  // here we actually need to encrypt the packet!
  // put it in the safebox!
  // in this example we're just forwarding the data
  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}
```

#### From tunnel to TUN

```C
void socketSelected (int tunfd, int sockfd){
  int len;
  char buff[BUFF_SIZE];

  printf("got a packet from the tunnel\n");
  // here we need to decrypt the data!
  // in this example we're just receiving the data
  bzero(buff, BUFF_SIZE);
  len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
  write(tunfd, buff, len);
}
```

## 9.8 Set Up a VPN

### Network Setup

- Host U wants to talk to Host V
  - U
    - tun0 10.4.2.99
  - V
    - tun0 10.4.2.5
    - vpn server 192.168.60.5
    - host v     192.168.60.6
    - network    192.168.60.0/24
  - VPN
  - Set up routing

- $ sudo route add -net 10.4.2.0/24 gw 192.168.60.5 eth19
  - run on the private network routers
- $ sudo route add -net 10.4.2.0/24 tun0
  - run on the VPN server
  - run on Host U
- $ sudo route add -net 192.168.60.0/24 tun0
  - run on the vpn client (host u)

## 9.9 Find the ip address


- host 128.230.0.0/16
<img src=./images/9_9_route_table.png>
- what is Computer's real IP address (addres of wifi card)?
  - 10.1.56.64
- What is the IP address of the VPN server?
  - 128.230.153.11
- What is the IP address of my TUN interface?
  - 128.230.153.98

## 9.10 Bypassing Firewalls Using VPN


## 9.11 Summary

- concept of VPN
- how VPN works
  - ssl/tls vpn
  - tun/tap interface
  - routing setup
- VPN implementation (code explanation)
- bypassing firewalls using VPN


