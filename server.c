#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <sys/ipc.h>
#include <sys/select.h>
#include <mqueue.h>
#include <errno.h>
#include <netinet/ip.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define IF_NAME "toto0"
#define UDP_PORT 55556
#define TCP_PORT 55555
#define BUFSIZE 4096
#define MSGSIZE 8192
#define MAX_CONNECTION 10
#define KEY_LEN 16
#define SHA256_LEN 32
#define MAX_COUNT 100
#define HOME "./ca/"
#define CACERT HOME "ca.crt"
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define KEY "abcdefghijklmnop"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";


void usage()
{
        fprintf(stderr, "Usage: server [-s port|]\n");
        exit(0);
}


int do_hmac(unsigned char *key, unsigned char *intext, int inlen, unsigned char *outbuf)
{
	int outlen;
	
	HMAC_CTX mdctx;
	HMAC_CTX_init(&mdctx);
	HMAC_Init_ex(&mdctx,key,KEY_LEN,EVP_sha256(),NULL);
	HMAC_Update(&mdctx,intext,inlen);
	HMAC_Final(&mdctx,outbuf,&outlen);
	HMAC_CTX_cleanup(&mdctx);
	return outlen;
		
}


int 
do_crypt(unsigned char *key, unsigned char *iv, unsigned char* intext, int inlen, unsigned char *outtext, int do_encrypt)
{
	unsigned char outbuf[BUFSIZE];
        int outlen,templen;

        EVP_CIPHER_CTX ctx;
        /* Don't set key or IV right away; we want to check lengths */
        EVP_CIPHER_CTX_init(&ctx);
        EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);
	if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, intext, inlen)){
		perror("EVP_CipherUpdate");
	}
	if(!EVP_CipherFinal_ex(&ctx, outbuf+outlen, &templen)){
		//perror("EVP_CipherFinal_ex");
	}
	outlen=outlen+templen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	memcpy(outtext, outbuf,outlen);

	return outlen;
}


void gethash(unsigned char *plaintext, unsigned char *md_value)
{
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        int md_len, i;

        OpenSSL_add_all_digests();

        md = EVP_get_digestbyname("sha256");

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, plaintext, strlen(plaintext));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);
        /* Call this once before exit. */
        EVP_cleanup();

}

unsigned char* getkey()
{
        unsigned char * key = (unsigned char *)malloc(sizeof(unsigned char)*KEY_LEN);
        FILE* random = fopen("/dev/urandom","r");
        fread(key, sizeof(unsigned char)*KEY_LEN,1,random);
        fclose(random);
        return key;
}


int iwrite(int fd, char *buf, int n)
{
	int len;
	
	if((len = write(fd, buf, n)) < 0)
	{
		perror("writing data error");
		exit(1);
	} 

	return len;
}

int iread(int fd, char *buf, int n)
{
	int len;
	
	if((len=read(fd, buf, n))<0){
    		perror("Reading data");
  		exit(1);
  	}

  return len;
}


int main(int argc, char *argv[])
{
        struct sockaddr_in saddr, caddr,sin, sout, from;
        struct ifreq ifr;
        int fd, s, fromlen, soutlen, port, PORT, l;
        char c, *p, *ip;
        char buf[BUFSIZE];
	unsigned char *plainbuf, *cryptbuf, *hmacbuf, *tmpbuf;
        unsigned char *key, *iv;
	int plainlen, cryptlen;
        fd_set fdset;

        int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

	plainbuf = malloc(BUFSIZE);
        cryptbuf = malloc(BUFSIZE);
        hmacbuf = malloc(BUFSIZE);
        tmpbuf = malloc(BUFSIZE);
        key = malloc(KEY_LEN);
        iv = malloc(KEY_LEN);
        strncpy(key,KEY, KEY_LEN);

        while ((c = getopt(argc, argv, "s:ehd")) != -1) {
                switch (c) {
                case 'h':
                        usage();
                case 'd':
                        DEBUG++;
                        break;
                case 's':
                        MODE = 1;
                        PORT = atoi(optarg);
                        break;
                case 'e':
                        TUNMODE = IFF_TAP;
                        break;
                default:
                        usage();
                }

	} 
	if (MODE == 0) usage();
///////////////////////////////////////////////////////////////////////////////////////////
//allocate tun/tap interface 
//dev name is toto0 if you are the first one to connect
	
	if ( (fd = open("/dev/net/tun",O_RDWR)) < 0) PERROR("open");

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = TUNMODE;
        strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
        if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

	printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	
	if ( (s=socket(PF_INET, SOCK_DGRAM, 0))<0 )
	{
		perror("UDP: socket()");
		close(fd);
		close(s);
	}
	
	memset(&saddr,0,sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);
	if ( bind(s,(struct sockaddr *)&saddr, sizeof(saddr)) < 0) PERROR("bind");
	
	fromlen = sizeof(from);

////////////////////////////////////////////////////////////////////////////////////////////
//authentication code
	while(1)
	{
		l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
		if(l < 0) PERROR("recevfrom");
		if(strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
			break;
		printf("Bad magic word from %s:%i\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port));
		
	}
	l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
	if(l<0) PERROR("send to");

	printf("Connection with %s:%i established\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port));


//////////////////////////////////////////////////////////////////////////////////////////////////
//Send and receive packets	
	while(1){

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		FD_SET(s, &fdset);
		if(select(fd+s+1, &fdset, NULL, NULL, NULL) < 0) PERROR("select");
		if(FD_ISSET(fd, &fdset)){
			if(DEBUG) write (1,">",1);
			l = iread(fd, buf, sizeof(buf));
			if( l != -1)
                        {       //do encryption
                                iv = getkey();
                                cryptlen = do_crypt(key, iv, buf, l, cryptbuf, 1);
                                memcpy(tmpbuf,iv,KEY_LEN);
                                memcpy(tmpbuf+KEY_LEN, cryptbuf, cryptlen);

                                //hmac inclued iv + encrypted data
                                do_hmac(key,tmpbuf,KEY_LEN+cryptlen,hmacbuf);

                                //copy iv, encrypted data and hmac into buf and then send
                                memcpy(buf, iv, KEY_LEN);
                                memcpy(buf+KEY_LEN, cryptbuf, cryptlen);
                                memcpy(buf+KEY_LEN+cryptlen, hmacbuf, SHA256_LEN);
                                int buflen = KEY_LEN + cryptlen + SHA256_LEN;

                                if(sendto(s, buf, buflen, 0, (struct sockaddr *)&from, fromlen) < 0)
                                        PERROR("send to");
                        }
		}
		if(FD_ISSET(s, &fdset)){
			if(DEBUG) write(1,"<",1);
			l = recvfrom(s, buf, sizeof(buf),0,(struct sockaddr *)&sout, &soutlen);
			if((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
				 printf("Got packet from  %s:%i instead of %s:%i\n",
                                       inet_ntoa(sout.sin_addr), ntohs(sout.sin_port),
                                       inet_ntoa(from.sin_addr), ntohs(from.sin_port));

                        memcpy(cryptbuf, buf, l-SHA256_LEN);
                	memcpy(iv, buf, KEY_LEN);
                	// do hmac to check the signature, if matches, decrypt the data
               		do_hmac(key,cryptbuf,l-SHA256_LEN,hmacbuf);
                	if (memcmp(hmacbuf, buf+l-SHA256_LEN, SHA256_LEN) == 0 && l!= -1)
                	{
                        	//do decryption, need to exclude iv and hmac
                        	plainlen = do_crypt(key, iv,cryptbuf+KEY_LEN,l-KEY_LEN-SHA256_LEN, plainbuf, 0);
                        	iwrite(fd, plainbuf, plainlen);
                	}
               		else{
                        	printf("ERROR, message check failed.\n");
                        	printf("message length: %d\n", l);
                	}
		}	
	}
}
