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
#define SERVERNAME "ho.duan"
#define IF_NAME "toto0"
#define PORT 10001
#define TCP_PORT 10002
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
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";


void usage()
{
        fprintf(stderr, "Usage: client [targetip]\n");
        exit(0);
}


int
do_hmac(unsigned char *key, unsigned char *intext, int inlen, unsigned char *outbuf)
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


SSL_CTX* myctx(){

        const SSL_METHOD *meth = SSLv23_client_method();
        SSL_CTX* ctx;
        X509 *cert;
        
        SSL_load_error_strings();
        SSL_library_init();//OpenSSL_add_ssl_algorithms() and SSLeay_add_ssl_algorithms() are synonyms for SSL_library_init(). 
        ctx = SSL_CTX_new (meth); CHK_NULL(ctx);
        if(!ctx){
                ERR_print_errors_fp(stderr);
                exit(2);
        }

        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
        return ctx;
}

// verify the common name on the server's certificate, return 1 on success, 0 for failure
int checkCN(SSL *ssl)
{
	X509 *cert;
        cert=SSL_get_peer_certificate(ssl);
        if(!cert) {
                perror("SSL_get_peer_certificate");
                exit(1);
        }

        X509_NAME *subject = X509_get_subject_name(cert);
        if (!subject) {
                perror("X509_get_subject_name");
                exit(1);
        }

        char *str = X509_NAME_oneline(subject,0,0);
        if (!str){
                perror("X509_NAME_oneline");
                exit(1);
        }

        OPENSSL_free(str);

        int nid_cn=OBJ_txt2nid("CN");
        char common_name[256];
        X509_NAME_get_text_by_NID(subject, nid_cn, common_name, 256);
        printf("CN: %s\n", common_name);
        char *servername="ho.duan";
        if(strncmp(common_name, servername, strlen(servername))==0){return 1;} 
	else {printf("\ncommon name check failed\n");return 0;}

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

void cleantcp(SSL* ssl, SSL_CTX* ctx, int sock_fd)
{
	if(sock_fd!=-1) close(sock_fd);
	if(ssl!=NULL) SSL_free(ssl);
	if(ctx!=NULL) SSL_CTX_free(ctx);
	exit(1);
}

void cleanudp(int fd, int s)
{
	if (fd!=-1) close(fd);
	if (s!=-1) close(s);
	exit(1);
}


void launchtcp(char *address, char* credential, struct sockaddr_in udpaddr, unsigned char* key)
{
	int sock_fd;
	int l, i, err;
	struct sockaddr_in saddr, caddr;
	char buf[BUFSIZE];
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(TCP_PORT);
	inet_aton(address, &saddr.sin_addr);

	// socket
	if((sock_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket() error!");
		//cleanuptcp(NULL,NULL,sock_fd,mq_fd,mq_fd_tcp,1);
	}
	// connect
	if( (connect(sock_fd, (struct sockaddr*) &saddr, sizeof(struct sockaddr))) <0 )
	{
		perror("connect() error!");
		//cleanuptcp(NULL,NULL,sock_fd,mq_fd,mq_fd_tcp,1);
	}
	printf("Initial TCP connection with server.\n");
	
	// send username password
	char temp[BUFSIZE];
	int templen;
	char tempbuf[BUFSIZE];	
	SSL* ssl;
	SSL_CTX* ctx = myctx();
	
	printf("%s\n", credential);
	templen = sprintf(temp,"%s%s", credential,":");
	memcpy(temp+templen, key, KEY_LEN);
	templen = templen + KEY_LEN;
	printf("%d:%s",strlen(temp), temp);	
	ssl = SSL_new(ctx);  CHK_NULL(ssl);
	if(!ssl){
		perror("SSL_new");
		cleantcp(ssl,ctx,sock_fd);
	}
	SSL_set_fd(ssl,sock_fd);	
	
	err = SSL_connect(ssl); CHK_SSL(err);
	if(err != 1) {
		perror("ssl_connect");
		cleantcp(ssl,ctx,sock_fd);
	}

	if(checkCN(ssl) != 1){
		printf("Invalid common name.");
		exit(1);
		cleantcp(ssl,ctx,sock_fd);
	}
	
	l=SSL_write(ssl,temp,templen);

	// clean credential, key, iv
	memset(credential, 0, strlen(credential));
	memset(temp, 0, templen);
	memset(key, 0, KEY_LEN);
	
	l = SSL_read(ssl, buf, BUFSIZE);
	char *msg = "Authorization failed, disconnect with client.";
	if(memcmp(msg, buf, strlen(msg)) ==0){printf("authorization failed");}
	else printf("Connection with %s:%i established\n",inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));


}

int main(int argc, char *argv[])
{
        struct sockaddr_in saddr, caddr,sin, sout, from;
        struct ifreq ifr;
        int fd, s, fromlen, soutlen, port,CPORT, l;
        char c, *p, *ip;
        char buf[BUFSIZE];
	unsigned char *plainbuf, *cryptbuf, *hmacbuf, *tmpbuf;
	unsigned char *key, *iv;
        fd_set fdset;
	int plainlen, cryptlen;


        int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

	plainbuf = malloc(BUFSIZE);
	cryptbuf = malloc(BUFSIZE);
	hmacbuf = malloc(BUFSIZE);
	tmpbuf = malloc(BUFSIZE);
	key = malloc(KEY_LEN);
	iv = malloc(KEY_LEN);
	strncpy(key,KEY, KEY_LEN);


	char * credential;
        credential = malloc(12);
        memcpy(credential, "user:userpwd", 12);
	printf("%s\n",credential); 
/*        while ((c = getopt(argc, argv, "c:ehd")) != -1) {
                switch (c) {
                case 'h':
                        usage();
                case 'd':
                        DEBUG++;
                        break;
                case 'c':
                        MODE = 2;
                        p = memchr(optarg,':',16);
                        if (!p) ERROR("invalid argument : [%s]\n",optarg);
                        *p = 0;
                        ip = optarg;
                        port = PORT;
                        CPORT = 0;
                        break;
                case 'e':
                        TUNMODE = IFF_TAP;
                        break;
                default:
                        usage();
                }

	}

	if (MODE == 0) usage();
*/

//////////////////////////////////////////////////////////////////////////////////

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
	
	memset(&caddr,0,sizeof(caddr));
	caddr.sin_family = AF_INET;
	caddr.sin_addr.s_addr = htonl(INADDR_ANY);
	caddr.sin_port = htons(PORT);
	if ( bind(s,(struct sockaddr *)&caddr, sizeof(caddr)) < 0) PERROR("bind");
	
	fromlen = sizeof(from);

////////////////////////////////////////////////////////////////////////////////////////////
/* Authentication Part*/

key = getkey();
int index;
for(index=0;index<strlen(key);index++){printf("%02x",key[index]);}

launchtcp(argv[1], argv[2], caddr,key);

/*
////////////////////////////////////////////////////////////////////////////////////////////
//authentication code
	from.sin_family = AF_INET;
	from.sin_port = htons(port);
	inet_aton(ip, &from.sin_addr);
	l = sendto(s, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
	if(l < 0) PERROR("sendto");
	l = recvfrom(s, buf, sizeof(buf), 0,(struct sockaddr *)&from, &fromlen);
	if(l<0) PERROR("recvfrom");
	if(strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) != 0)
		ERROR("Bad magic word from peer\n");

	 printf("Connection with %s:%i established\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port));
*/
//////////////////////////////////////////////////////////////////////////////////////
//fetch and send packets 
/*
while(1){
	
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	FD_SET(s, &fdset);
	if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
        if (FD_ISSET(fd, &fdset)) {
                        if (DEBUG) write(1,">", 1);
                        l = iread(fd, buf, sizeof(buf));
			if( l != -1)
			{	//do encryption
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
		if (DEBUG) write(1,"<", 1);
                l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);
                if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
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
*/
}
