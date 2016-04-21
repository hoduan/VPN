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
#define UDP_PORT 10001
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

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


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

SSL_CTX* myctx(){
	
	SSL_CTX *ctx;
	const SSL_METHOD *meth = SSLv23_server_method();
	//initialize
	SSL_load_error_strings();
	SSL_library_init();
  	//create ctx
	ctx = SSL_CTX_new (meth);
  	if (!ctx) {
    		ERR_print_errors_fp(stderr);
   		exit(2);
	}
	
	//Do not verify client certificate from the server side
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	//load ca.crt
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
	//set server's crt
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(3);
        }
	// set server private key
        if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(4);
        }
	

        // private key and certificate consistency
        if (!SSL_CTX_check_private_key(ctx)) {
                fprintf(stderr,"Private key does not match the certificate public key\n");
                exit(5);
        }
	else{printf("\nkey and certificate consistency checked\n");}

        return ctx;

	
}

//check user record, return 1 on success, 0 on failure
int usercheck(char *buf){
	char *msg = malloc(BUFSIZE);
	memcpy(msg, buf, strlen(buf));
	unsigned char *user, *pwd;	
	unsigned char phash[32];
	unsigned char hash[64];
	char tmp[BUFSIZE];
	int i;
	
	user = strtok(msg, ":");
	pwd = strtok(NULL,":");
	gethash(pwd, phash);
	int index;
	//for(index=0;index<strlen(phash);index++){printf("%02x",phash[index]);}

	
	for(i = 0; i<32; i++)
	{
		sprintf(hash+i*2, "%02x", phash[i]);
	}
	
	//for(index=0;index<strlen(phash);index++){printf("%02x",phash[index]);}


		memcpy(tmp, user, strlen(user));
		memcpy(tmp+strlen(user), ":",1);
		memcpy(tmp+strlen(user)+1, &hash, 64);
		memcpy(tmp+strlen(user)+1+64, "\x0a",1); // add a newline character	
		FILE *f;
		size_t len;
		char* line;
		f = fopen("data.txt", "r");
		if(f == NULL) {perror("the data file is null, nothing stored there!"); return 0;}
		while((getline(&line, &len, f))!=-1)
		{
			if((memcmp(line, tmp, strlen(tmp)) ==0) && (strlen(tmp) == strlen(line)))
			{
				printf("\nAuthorization checking passed!\n");
				return 1;
				break;
			}
		}
	return 0;
	
}


unsigned char* getkey()
{
        unsigned char * key = (unsigned char *)malloc(sizeof(unsigned char)*KEY_LEN);
        FILE* random = fopen("/dev/urandom","r");
        fread(key, sizeof(unsigned char)*KEY_LEN,1,random);
        fclose(random);
        return key;
}

void launchudp(struct sockaddr_in caddr,unsigned char *key)
{
	struct sockaddr_in saddr,sin, sout, from;
        struct ifreq ifr;
        int fd, s, fromlen, soutlen, port, l;
        char c, *p, *ip;
        char buf[BUFSIZE];
	unsigned char *plainbuf, *cryptbuf, *hmacbuf, *tmpbuf;
        unsigned char *iv; //*key;
	int plainlen, cryptlen;
        fd_set fdset;

        int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 1;

	plainbuf = malloc(BUFSIZE);
        cryptbuf = malloc(BUFSIZE);
        hmacbuf = malloc(BUFSIZE);
        tmpbuf = malloc(BUFSIZE);
        //key = malloc(KEY_LEN);
        iv = malloc(KEY_LEN);


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
	saddr.sin_port = htons(UDP_PORT);
	if ( bind(s,(struct sockaddr *)&saddr, sizeof(saddr)) < 0) PERROR("bind");
	
	memcpy(&from,&caddr,sizeof(caddr));
	from.sin_port = htons(UDP_PORT);
	fromlen = sizeof(from);
	/*while(1)
	{
		l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
	if(l>0) {printf("testing");}	
	if(l < 0) PERROR("recevfrom");
		if(strncmp("Hello", buf, sizeof("Hello")) == 0)
			break;
	}

	printf("Connection with %s:%i established\n",
               inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	*/
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

launchtcp()
{
	int server_tcp_fd, client_fd, i;
	struct sockaddr_in saddr, caddr;
	int l,err, optval =1;
	pid_t child_pid;
	socklen_t len;
	unsigned short int port = TCP_PORT;
	unsigned char *key;
	key = malloc(KEY_LEN);
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(port);
	

	// create socket
        if ( (server_tcp_fd=socket(AF_INET,SOCK_STREAM,0)) < 0)
        {
                perror("TCP: socket() error!");
                exit(1);
        }

        /* avoid EADDRINUSE error on bind() */
        if(setsockopt(server_tcp_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
                perror("TCP: setsockopt() error!");
                exit(1);
        }

        // bind port
        if ( (bind(server_tcp_fd,(struct sockaddr*) &saddr, sizeof(saddr))) <0 )
        {
                perror("TCP: bind() error!");
                exit(1);
        }
        // listen
        if ( (listen(server_tcp_fd, 10)) < 0 )
        {
                perror("TCP: listen() error!");
                exit(1);
        }
        printf("TCP: Launch TCP server on PORT: %d\n",port);
        // accept if any


		len = sizeof(struct sockaddr_in);
		memset(&caddr, 0, len);
		client_fd = accept(server_tcp_fd, (struct sockaddr*) &caddr, &len);
		char buf[BUFSIZE];
		printf("TCP: Initial connection with IP: %s\n", inet_ntoa(caddr.sin_addr));
/////////////////////////////////////////////////////////////////////////////////////////
//create ctx
		SSL* ssl;
		ssl = SSL_new (myctx());  CHK_NULL(ssl);
		if(!ssl){perror("ssl_new error"); exit(1);}
		 /* TCP connection and ssl are ready. Do server side SSL. */
		SSL_set_fd (ssl, client_fd);
		err = SSL_accept(ssl); CHK_SSL(err);
  		if(err == -1)
			{	
				ERR_print_errors_fp(stderr); 
				exit(2);
			}
		 
	
		memset(&buf, 0, sizeof(buf));
		l = SSL_read(ssl, buf, BUFSIZE);
		if (l > 0)
		{
			//client authentication
			if(usercheck(buf) == 1)
			{
				for(i=0;i<KEY_LEN;i++)
                                {
                                        key[i] = buf[l-KEY_LEN+i];
                                }

                                int index;
                                for(index=0;index<KEY_LEN;index++)
                                {
                                        printf("%02x",key[index]);
                                }

				char *msg = "Authentication passed, connected with client";
				l = SSL_write(ssl, msg, strlen(msg));
				printf("Connection with %s:%i established\n",inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
			}

			else 
			{
				char *msg="Authorization failed, disconnect with client.";
				l=SSL_write(ssl,msg,strlen(msg));
				printf("%s\n",msg);
				close(client_fd);
				exit(0);
			}

		}

		launchudp(caddr,key);
}

int main(int argc, char *argv[])
{

launchtcp();

return 0;

}
