# Week 7 Secret Key Encryption and One-way Hash Function

## Directory
- [Home](/README.md#table-of-contents)
- [Week 6 DNS](/week6/README.md#Week-6-DNS)
- **&rarr;[Week 7 Secret Key Encryption and One-way Hash Function](/week7/README.md#Week-7-Secret-Key-Encryption-and-One-way-Hash-Function)**
- [Week 8 Public-Key Encryption and PKI](/week8/README.md#Week-8-Public-Key-Encryption-and-PKI)

## SSL (Secure Socket Layer)
- transport layer security service
- two layer protocol
  - ssl connection
    - peer to peer
    - associated with 1 ssl session
  - ssl session
    - an association between client and server
    - created by the handshake protocol
    - define a set of cryptographic parameters
    - may be shared by multiple ssl connections
- ssl record protocol srevices
  - confidentiality
    - using symmetric encryption with a shared secret key defined by Handshake protocol
    - message is compressed before encryption
  - message integrity
    - using a MAC with shared secret key
    - similar to HMAC but with different padding

# Week 7: Secret Key Encryption and One-way Hash Function
## 7.2 Secret-Key Encryption

### Introduction to Cryptography
- What is security?
- C I A
- Confidentiality
  - packet sniffing
  - steal password
- Integrity
  - spoofing
  - dns cache poison
  - arp cache poison
  - TCP session hijacking
  - man in the middle
- Availability
  - denial of service
  - SYN flooding
  - TCP RST

- Cryptography helps solves
  - confidentiality
  - integrity

- Secret Key Encryption (Symmetric Key)
- Public Key Encryption (Asymmetric Key)
- One-way hash

## 7.3 Classical Cryptosystems

### Classical Cryptosystems
- Substitution Cipher
  - 2000 yo, caesar cipher
  - A -> H
  - B -> Z
  - C -> I
  ...
  - Z -> O
- plaintext
  - hello
- ciphertext
  - xtbbw

- Monoalphabetic Substitution Cipher
- Polyalphabetic Substitution Cipher

### One-Time Pad
- Message
- Key
- message -xo- key => cipher text

- Cannot reuse the key

## 7.4 DES: Data Encryption Standard

### DES History
- IBM
  - Host Fiestel - "Lucifer"
- 1974 NIST
  - Want to standardize DES
- NSA wants to break crypto
  - First Crypto War
    - 64-bit key
      - 56-bits due to error
- Cracked in 1998 by brute force

## 7.5 AES: Advanced Encryption Standard

- NIST 2001
  - Rijndael (Rain Roll)
- Key size
  - 128
  - 192
  - 256

## 7.6 How to Encrypt Multiple Blocks

### Encrypt more than one block
#### ECB: Electronic Codebook
- Single block cipher
  - DES
    - 64 bit block
  - AES
    - 128 bit block
  - have to encrypt each block separately, otherwise we can establish a pattern between multiple ciperblocks
<img src='./images/7_6_blockcipher.png' width=750>

## 7.7 Encryption Modes

### Cipher Block Chaining (CBC) Mode

**Block Cipher**
<img src='./images/7_6_blockcipher_actual.png' width=750>

- Initialization Vector (IV)
  - Initialization Vector allows us to reuse the same block ciper logic in hardware
  - Initialization Vector changes the first cipher block, thus changing the whole cipher 
  - IV not secret, but needs to be random and unique

### Cipher Feedback (CFB)

**Stream Cipher**
<img src='./images/cipher_feedback.png'>
- IV feeds into block cipher encryption first
- main difference
  - don't need full plaintext because the IV is always there. xor works with full IV against partial plaintext

### Output Feedback (OFB)

<img src='./images/output_feedback.png'>

- don't need to wait for plaintext to create the cipher
- can complete encryption in parallel 
  - offline help

### Counter Mode (CTR)
<img src='./images/counter_mode.png'>

- no chaining
- stream cipher
- but the counter and nonce change, so the ciphertext changes even if the plaintext is the same
- parallel encryption without offline help


- if a bit is corrupted, only that block and one bit of the next block will be corrupted.

## 7.8 Padding
- block cipher needs whole plaintext to chain
### Padding: PKCS#5

## 7.9 Random Number Generation
### why do we need ranom numbers?

- key!

```C
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
  int c,n;
  printf("ten random numbers in [1,100]\n");
  for (c=1; c<=10;c++){
    n=rand()%100 +1;
    printf("%d\n",n);
  }
  return 0;
}
// Predictable - not secure!!
```

```C
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
  int c,n;
  srand(time(NULL));// have to set the seed
  printf("ten random numbers in [1,100]\n");
  for (c=1; c<=10;c++){
    n=rand()%100 +1;
    printf("%d\n",n);
  }
  return 0;
}
// Predictable - not secure!!
// if the seed is predictable, the random is predictable
```

### Wehere do get true randomness
- get help from human/physical world

- user
  - move mouse
  - type keys
- hardware
  - temperature of a cpu
  - timing of the interrupt

- Linux
  - a random pool
    - get random data from the ppol
    - `/dev/random`
      - block
    - `/dev/urandom`
      - nonblocking

### Generate a random 128-bit key
```C
#define LEN 16 //128 bits

unsigned char *key = (unsigned char *) malloc(sizeof(char)*LEN);
FILE* random = fopen("/dev/urandom","r");
fread(key, sizeof(char)*LEN,1,random);
fclose(random);
```

### User Special Hardware
- quantum random number generator

## 7.10 Summary
- Classical Ciphers
- DES and AES
- Encryption Modes
- Random number generator

## 7.11 One-way Hash Function

### A game with online students
- Student pick number A
- Student pick number B
- A+B
  - if even student wins
  - if odd prof wins
- Student sends # first
  - prof always wins

## 7.12 Concept of One-way Hash
### Concept
- hash: data -> fixed size
- modulo is a hash function
  - `m % 100` = 0...99
- **one way**
  - `hash(M) = h`
  - cannot find *any* `M` given `h` and `hash()`
  - find `M'` such that `hash(M') = h`
    - difficult
- **collision free**
  - find `M_1`, `M_2`, (`M_1!=M_2`)
  - `hash(M_1)=hash(M_2)`

### Algorithms
- MD: Message Digest
  - MD2, MD4, MD5
- SHA: Secure Hash Algorithm
  - SHA0
  - SHA1
  - SHA2
    - 256-bit SHA-256
    - 384-bit SHA-384
    - 512-bit SHA-512

## 7.13 replay the game
- Prof sends hash(A) to sudent
- Sudent sends B
- prof sends A

- one way property
  - fair to professor
- collision free
  - fair to student

## 7.14 More Applications
### Application: Time Stamping
- publish the hash of a book because 512 bits is cheaper to publish than a whole book

### Application: Password Authentication
- username
- password

- store password in plaintext?
  - store in one-way hash

## 7.15 Message Authentcation Code
### MAC: Message Authentication Code
- A sends message M to B
  - ensure that integrity of M is not changed by man in the middle (mitm)
1. send M, hash(M)
   - doesn't work because mitm can change to M' and hash(M')
2. assume A and B have secret key k
   - encrypt_k(M)
3. M, hash(M || k)
   - send hash of message and encryption key
   - **MAC**

### HMAC
**standard**
$HMAC_K(m)=h((K\oplus{}opad)||h(K\oplus{}ipad||m))$

## 7.16 Collision-Free is Broken
MD5 - found collisions

## 7.17 Summary
- one-way hash function
  - one-way property
  - collision-free property
- algorithms
- applications
  - online game
  - time stamping
  - message authentication code
  - HMAC
