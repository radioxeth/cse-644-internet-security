
# Week 8: Public-Key Encryption and PKI

## 8.2 Public-Key Encryption
### Public-Key Cryptography: History and Concept

- how to solve the key exchange problem?
  - need to encrypt to share the key

1. 1969
   - Jame Ellis
   - no-secret key for encryption
     - public
   - secret key for decryption
     - private

2. 1976
   - whitfield diffie/martin hellman
   - diffie-hellman key exchange

3. 1976
   - Rivst Shamir Adleman: RSA
   - First secure public key algorithm
4. 1973
   - Clifford Cocks
   - GCHQ (classified)

## 8.3 Diffie-Hellman Key Exchange
- Alice
- Bob
- Eve

Alice and Bob want to find a common secret, `k`. Eve can observe their communication.

- Discrete Logrithm
  - $g^x\mod{p}=b$
  - hard to find x

Alice and Bob agree on two numbers with mathematical properties (not a secret)
Alice sends $g^x\mod{p}$ and Bob sends $g^y\mod{p}$
Alice computes $(g^y\mod{p})^x\mod{p}$
Bob computes $(g^x\mod{p})^y\mod{p}$
remove inside mod
$g^{xy}\mod{p}$ common number known by Bob and Alice.


### Turn DH to Public-Key Encryption
- Alice knows
  - g, p, x
    - x is private
  - public key
    - $g^x\mod{p}$
- Bob knows
  - y
  - calculates $(g^x\mod{}p)^y\mod{p}$
    - $g^{xy}\mod{p}$
      - use this as key to encrypt (AES, DES etc) the message
      - need to send $g^y\mod{p}$ so Alice can decrypt

## 8.4 RSA Public-Key Encryption Algorithm

### RSA Algorithm
- Factoring large numbers is hard.
- Fact: `p`, `q` prime numbers
  - `n=pq`
  - from `n` can you find `p` and `q`
  - hard

- Algorithm
  - public key `n`
    - `n=pq`
    - safe guard p & q, n is public
    - (e,n)
      - e=2^16+1=65537 (prime)
        - e is public
  - private key `d`
    - $M^e\mod{n}=C$
    - $(M^e\mod{n})^d\mod{n}=C$
      - decryption to get M back, M is message
      - $M^{ed}\mod{n}=M$
      - find d
        - e=1,d=1 - no good! (even though it works)
      - $M^{ed-1}\mod{pq}=1$
        - $ed-1=(p-1)(q-1)$
        - $ed=(p-1)(q-1)+1$
        - $ed=K(p-1)(q-1)+1$
        - $ed\mod{(p-1)(q-1)}=1$
          - extended euclidean algorithm
          - solve for `e` from `p` and `q`

    - Euler Theorem
      - for any m < p and q
        - $M^{(p-1)(q-1)}\mod{pq}=1$

## 8.5 Exercise Related to RSA

### Summarize RSA
- n=pq
- pick e, not secret 2^16+1=65537
- solve $ed\mod{(p-1)(q-1)=1}$, find d
  - public key (e,n)
  - pivate key (d,n)

- encryption
  - $M^e\mod{n}$
- decryption 
  - $C^d\mod{n}$

### Exercise
n=33, e=17

p=3,q=11
$17d \mod{(2*10)}=1$
d=13

encrypt
$31^17\mod{33}$

dont just raise to 17

just use rsa for public key exchange because it is  expensive. After that use symetric key

## 8.6 Man-in-the-Middle Attack
- Alice
- Bob

- Alice sends (e,n) to Bob in plaintext
  - okay if Eve is listening
- What if eve is in the middle?
  - Alice sends (e,n), intercepted by Attacker
  - Attacker sends (e',n')=pk' to Bob
  - Bob encrypts using $enc_{pk'}(M)$
    - attacker decrypts M
  - Attacker sends $enc_pk(M)$ back to Alice
    - M is from Bob
- difficult to launch this attack, but is possible

## 8.7 Digital Signature

- Alice sends (e,n)
  - how do we verify that (e,n) belongs to alice?
  - need someone to put a digital signature or seal on the public key
- RSA 
  - $M^e\mod{n}$ encryption
  - $M^d\mod{n}$ signature
    - only Alice can generate the signature
    - use the public key $(M^d\mod{n})^e\mod{n}=M$
  - attacker can chane M->M', but won't be able to
- M->$hash(M)^d\mod{n}$

### Defeating MitM attack using Digital Signature
- Alice and Bob get signature from Trusted Party
- Bob needs to know the public key of the trusted party

## 8.8 X.509 Certificate

Alice: (e,n) signature


Certificate Authority (CA). Trusted party to sign public keys

2016
- comodo
- symantec (verisign)
- godaddy
- globalsign

- Self signed certificate
  - only trust the root CA self signed certificate

# 8.9 Exercise: The TLS/SSL Protocol
Transport Layer Security
## The TLS/SSL Protocol
- Client
- Server

- Share public key
  - expensive
- Key, session key
  - much faster

1. Server sends Client public key certificate
2. Client & server generates key using the public key
3. Switch to symmetric key

### Verify
- Client checks cert - is this yours?
  - send number, if you can decrypt it, you own the private key
- Is this vouched/signed by CA?
- Is it still valid?
  - Cert has expiration date
- Are you whome I want to talk to ??
  - you need to check the common name

## Setup of SSL


### Client Side
```C
SSL_load_error_strings(); //readable error messages
SSL_library_init(); //initialize library

// specify this is a client
meth = SSLv23_client_method();
ctx = ssl_CTX_new (meth);
if(!ctx){
  ERR_print_errors_fp(stderr);
  exit(2);
}

// will verify the server
SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

// set the location of the CA Cert
SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
```

### Server Side

```C
SSL_load_error_strings(); //readable error messages
SSL_library_init(); //initialize library

//specify this is a server
meth=SSLv23_server_method();
ctx=SSL_CTX_new(meth);
if(!ctx){
  ERR_print_errors_fp(stderr);
  exit(2);
}

// will not verify the client
SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);

// set the location of the CA Cert
SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

// prepare the certificate (the client will request it)
if(SSL_CTX_use_certificate_file(ctx, CERTF,SSL_FILETYPE_PEM)<=0{
  ERR_print_errors_fp(stderr);
  exit(3);
}

if(SSL_CTX_use_PrivateKey_file(ctx, KEYF,SSL_FILETYPE_PEM)<=0{
  ERR_print_errors_fp(stderr);
  exit(4);
}

if(!SSL_CTX_check_private_key(ctx)<=0{
  fprintf("stderr","Private key does not match the certificate public key\n");
  exit(5);
}


```

### Establish SSL Connection
#### CLIENT SIDE  

```C
sd = socket(AF_INET,SOCK_STREAM,0);
CHK_ERR(sd,"socket");

memset(&sa,'\0',sizeof(sa));
sa.sin_family= AF_INET;
sa.sin_addr.s_add=inet_addr("127.0.0.1");//server ip
sa.sin_port = htons(1111);//server port

err = connect(sd, (struct sockaddr*),&sa,sizeof(sa));
CHK_ERR(err,"connect");

//after tcp connection, start ssl
ssl=SSL_new(ctx);
CHK_NULL(ssl);
SSL_set_fd(ssl,sd);
err=SSL_connect(ssl);
CHK_SSL(err);
```

#### SERVER SIDE

```C
// prepare TCP socket for receiving conncetions

listen_sd = socket (AF_INET, SOCK_STREAM, 0); CHK_ERR(listen_sd,"socket");

memset (&sa_serv,'\0',sizeof(sa_serv));
sa_serv.sin_family = AF_INET;
sa_serv.sin_addr.s_addr = INADDR_ANY;
sa_serv.sin_port = htons(1111);

err=bind(listen_sd, (struct sockaddr*)&sa_server,sizeof(sa_serv)); CHK(err,"bind");

//receive tcp connection
err=listen(listen_sd,5); CHK(err,"listen");

client_len = sizeof(sa_cli);
sd=accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
CHK_ERR(sd,"accept");
close(listen_sd);
printf("connection from %lx,port %x\n"),sa_cli.sin_addr.s_addr,sa_cli.sin_port);

//tcp connection is ready, do server side SSL

ssl = SSL_NEW(ctx); CHK_NULL(ssl);
SSL_set_fd(ssl, sd);
err = SSL_accept (ssl); CHK_SSL(err);
```

```C
// get servers certificate (beware of dynamic allocation )
server_cert = SSL_get_peer_certificate(ssl); CHK_NULL(server_cert);
printf("Server certificate:\n");

// get the subject from the certficate
X509_NAME *subject = X509_get_subject_name (server_cert); CHK_NULL(subject);
str = X509_NAME_oneline(subject, 0, 0); CHK_NULL(str);
printf("\t subject: %s\n",str);
OPENSSL_free(str);

// get the common name field from the subject
int nid_cn = OBJ_txt2nid("CN");
char common_name[256];
X509_NAME_get_text_by_NID(subject, nid_cn,common_name, 256);
printf("\t CN: %s\n", common_name);
```

#### Better way to verify common names:

```C
#include <openssl/x509.h>

int X509_check_host(X509 *, const char *name, size_t namelen, unsigned int flags, char **peername);

int X509_check_email(X509 *, const char *address, size_t addresslen, unsigned int flags);

int X509_check_ip(X509 *, const char *address, size_t addresslen, unsigned int flags);

int X509_check_ip_asc(X509 *, const char *address, unsigned int flags)
```

#### Data Exchange and Clean Up

```C
//send a message and receive a reply
err = SSL_write (ssl, "Hello world!",strlen("Hello world!")); CHK_SSL(err);

err = SSL_read (ssl, buf, sizeof(buf)-1); CHK_SSL(err);

buf[err]='\0';
printf("got %d chars: '%d'\n",err,buf);
SSL_shutdown(ssl);//send ssl/tls close_notify

//cleanup
cose(sd);
SSL_free(ssl);
SSL_CTX_free(ctx);
```

## 8.10 The Trust on CA

### Root Certificate Authority (CA)

- survey result of april 2016
  - comodo group 40.6%
  - symantex 26.0%
  - goDaddy 11.8%
  - globalSign 9.7%

Protect the private key!

### If a CA is compromised
CA issues Certificate
CA Private key is stolen
- attacker can create fake certificates

Can launch man in the middle attack

### Certificate Pinning

- Browser
  - pin: google's certificate
  - check pinned certificate against received certificate

### Certificate Revocation List (CRL)
- list of revoked certificates
  - software needs to check.

## 8.11 Application: DNSSEC

### DNSSEC
- request
- reply
  - mintm sends fake reply
- Chain of trust by sending one way hash of child's public key
  - doesn't rely on certificate

## 8.12 Summary

- Public key encryption concept
- Diffie-hellman key exchange protocol
- RSA Algorithm
- man-in-the-middle attack
- Digital signature, X.509 certificate, and CA
  - Public Key Infrastructure
- TSL/SSL protocol
- case studies on CAs
- DNSSEC
