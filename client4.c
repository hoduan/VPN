#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
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
#include <fcntl.h>
#define UDP_PORT 10001
#define TCP_PORT 10002
#define BUFSIZE 4096
#define MSGSIZE 8192
#define MAX_CONNECTION 10
#define KEY_LEN 16
#define SHA256_LEN 32
#define MAX_COUNT 100
#define STDIN 0
#define HOME "./ca/"
#define CACERT HOME "ca.crt"
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


void usage()
{
        fprintf(stderr, "Usage: client [targethostname] [username:pwd]\n");
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
int checkCN(SSL *ssl, char *hostname)
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
        char *servername=strtok(hostname,".");
	servername = strtok(NULL," ");
        if(strncmp(common_name, servername, strlen(servername))==0 && (strlen(servername) == strlen(common_name))){return 1;} 
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
}


void launchtcp(char *address, char *hostname, char* credential)
{
	int tcp_fd;
	int l, i, err;
	struct sockaddr_in saddr, caddr, sout, from;;
	char buf[BUFSIZE];
	unsigned char *key;
	key = malloc(KEY_LEN);
	key = getkey();
	int index;
	//for(index=0;index<KEY_LEN;index++){printf("%02x",key[index]);}
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(TCP_PORT);
	inet_aton(address, &saddr.sin_addr);
	
	

	// socket
	if((tcp_fd=socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket() error!");
	}
	// connect
	if( (connect(tcp_fd, (struct sockaddr*) &saddr, sizeof(struct sockaddr))) <0 )
	{
		perror("connect() error!");
	}
	printf("Initial TCP connection with server.\n");
	
	// send username password
	char temp[BUFSIZE];
	int templen;
	char tempbuf[BUFSIZE];	
	SSL* ssl;
	SSL_CTX* ctx = myctx();
	
	templen = sprintf(temp,"%s%s", credential,":");
	memcpy(temp+templen, key, KEY_LEN);
	templen = templen + KEY_LEN;
	ssl = SSL_new(ctx);  CHK_NULL(ssl);
	if(!ssl){
		perror("SSL_new");
		cleantcp(ssl,ctx,tcp_fd);
		exit(1);
	}
	SSL_set_fd(ssl,tcp_fd);	
	
	err = SSL_connect(ssl); CHK_SSL(err);
	if(err != 1) {
		perror("ssl_connect");
		cleantcp(ssl,ctx,tcp_fd);
		exit(1);
	}

	if(checkCN(ssl,hostname) != 1){
		printf("Invalid common name.");
		cleantcp(ssl,ctx,tcp_fd);
		exit(1);
	}
	
	l=SSL_write(ssl,temp,templen);

	// clean credential
	memset(credential, 0, strlen(credential));
	memset(temp, 0, templen);
	
	l = SSL_read(ssl, buf, BUFSIZE);
	char *msg = "Authorization failed, disconnect with client.";
	if(memcmp(msg, buf, strlen(msg)) ==0){printf("\nAuthorization failed\n");cleantcp(ssl,ctx, tcp_fd);exit(1);}
	else printf("Connection with %s:%i established\n",inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));
	
	int c;
	int fds[2];
	unsigned char *newkey = malloc(KEY_LEN);
	pid_t childpid;
	pipe2(fds,O_NONBLOCK);
	childpid = fork();
	int status;
	memcpy(newkey, key, KEY_LEN);
	
	////////////////////////////////////////////////////////////////////////////
	//UDP data tunnle
	if(childpid == 0)
    	{	
		cleantcp(ssl,ctx, tcp_fd);
		
		struct ifreq ifr;
		int fd, s, fromlen, soutlen=sizeof(sout),mlen;
		unsigned char *plainbuf, *cryptbuf, *hmacbuf, *tmpbuf;
		unsigned char *iv,*tmpkey;
		fd_set fdset;
		char buffer[BUFSIZE];
		int plainlen, cryptlen;
		int TUNMODE = IFF_TUN, DEBUG = 1;
		int nbytes;
		plainbuf = malloc(BUFSIZE);
		cryptbuf = malloc(BUFSIZE);
		hmacbuf = malloc(BUFSIZE);
		tmpbuf = malloc(BUFSIZE);
		iv = malloc(KEY_LEN);
		tmpkey = malloc(KEY_LEN);

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
		caddr.sin_port = htons(UDP_PORT);
		if ( bind(s,(struct sockaddr *)&caddr, sizeof(caddr)) < 0) PERROR("bind");
	

		from.sin_family = AF_INET;
		from.sin_port = htons(UDP_PORT);
		inet_aton(address, &from.sin_addr);
		fromlen = sizeof(from);	
		while(1){
		
			FD_ZERO(&fdset);
			FD_SET(fd, &fdset);
			FD_SET(fds[0], &fdset);
			FD_SET(s, &fdset);
			if (select(fd+fds[0]+s+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
			if (FD_ISSET(fds[0], &fdset)) {
			    close(fds[1]);
			    nbytes = read(fds[0], tmpkey, KEY_LEN);
			    if(nbytes!=-1 && nbytes!=0)
			    { 
			    	//update key
			    	if(nbytes == 16)memcpy(newkey, tmpkey, KEY_LEN);
			    	//close connection
			    	if(nbytes == 1)
			    	{
			    		memset(key,0, KEY_LEN);
			    		memset(newkey,0,KEY_LEN);
			    		memset(tmpkey,0,KEY_LEN);
			    		memset(buffer,0, BUFSIZE);
			    		close(fd);
			    		close(s);
			    		exit(0);
			    	}
			    }
				
			}
			if (FD_ISSET(fd, &fdset)) {
				if (DEBUG) write(1,">", 1);
 		                mlen = iread(fd, buffer, sizeof(buffer));
				if( mlen != -1)
				{	//do encryption
					iv = getkey();
					cryptlen = do_crypt(key, iv, buffer, mlen, cryptbuf, 1);
					memcpy(tmpbuf,iv,KEY_LEN);
					memcpy(tmpbuf+KEY_LEN, cryptbuf, cryptlen);
				
					//hmac inclued iv + encrypted data
					do_hmac(key,tmpbuf,KEY_LEN+cryptlen,hmacbuf);
					
					//copy iv, encrypted data and hmac into buffer and then send
					memcpy(buffer, iv, KEY_LEN);
					memcpy(buffer+KEY_LEN, cryptbuf, cryptlen);
					memcpy(buffer+KEY_LEN+cryptlen, hmacbuf, SHA256_LEN);
					int buflen = KEY_LEN + cryptlen + SHA256_LEN;
				
					if(sendto(s, buffer, buflen, 0, (struct sockaddr *)&from, fromlen) < 0)
						PERROR("send to");
				}
			}

			if(FD_ISSET(s, &fdset)){
				if (DEBUG) write(1,"<", 1);
		                mlen = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr *)&sout, &soutlen);
				memcpy(cryptbuf, buffer, mlen-SHA256_LEN);
				memcpy(iv, buffer, KEY_LEN);
				// do hmac to check the signature, if matches, decrypt the data
				do_hmac(key,cryptbuf,mlen-SHA256_LEN,hmacbuf);
				//change key
				if(memcmp(hmacbuf, buffer+mlen-SHA256_LEN, SHA256_LEN) !=0 && memcmp(key, newkey, KEY_LEN)!=0)
				{	
					memcpy(key, newkey, KEY_LEN);
					do_hmac(key,cryptbuf,mlen-SHA256_LEN,hmacbuf);
					printf("\nupdated key in client:");
					for(i=0;i<16;i++) printf("%02x",key[i]);
					printf("\n");
				}
				if (memcmp(hmacbuf, buffer+mlen-SHA256_LEN, SHA256_LEN) == 0 && mlen!= -1)
				{	
					//do decryption, need to exclude iv and hmac
                        		plainlen = do_crypt(key, iv,cryptbuf+KEY_LEN,mlen-KEY_LEN-SHA256_LEN, plainbuf, 0);
                        		iwrite(fd, plainbuf, plainlen);
				}
					
				else{
					printf("ERROR, message check failed.\n");
					printf("message length: %d\n", mlen);
				}	

			}

		}
			
		exit(EXIT_SUCCESS);
	
	}
	
	
	///////////////////////////////////////////////////////////////////////////
	//TCP tunnle control
	else if(childpid > 0)
	{	
		while(1)
		{
			fd_set tcp_set;
			FD_ZERO(&tcp_set);
			FD_SET(tcp_fd,&tcp_set);
			FD_SET(STDIN,&tcp_set);
			
			select(tcp_fd+STDIN+1, &tcp_set, NULL, NULL, NULL); 
	
			if(FD_ISSET(STDIN, &tcp_set))
			{
				if(EOF != (c=fgetc(stdin)))
				{
					if(c == '1')
					{	close(fds[0]);
						newkey = getkey();
						templen = sprintf(temp,"%s%s","1",":");
						memcpy(temp+templen,newkey,KEY_LEN);
						templen=templen+KEY_LEN; 
						l = SSL_write(ssl, temp, templen);
						write(fds[1], newkey, KEY_LEN);
						printf("\nnew key genearte is:");
                                        for(i=0;i<16;i++)printf("%02x",key[i]);

					}
					if(c == '0')
					{	
						close(fds[0]);
						l= SSL_write(ssl,"0:0",3);
						write(fds[1],"0",1);
						cleantcp(ssl, ctx, tcp_fd);
						wait(&status);
						exit(0);
					}
				}
			}

			if(FD_ISSET(tcp_fd, &tcp_set))
			{
				l = 0;
				l = SSL_read(ssl, buf, BUFSIZE);
				if (l<0)
				{
					perror("TCP recerve msg error");
					cleantcp(ssl,ctx,tcp_fd);
					exit(1);
				}
				if (l > 0 )
				{
					printf("Received message: ");
					for (i=0; i<l; i++) printf("%c",buf[i]);
					printf("\n");	
				}
				else if (l==0)
				{
					printf("Server disconnect\n");
					cleantcp(ssl,ctx,tcp_fd);
					exit(1);
				}
			}
		}
	
	exit(EXIT_SUCCESS);	
	}
	else{perror("fork");exit(EXIT_FAILURE);}


}

int main(int argc, char *argv[])
{
	char * ip;
	struct hostent *serverHost;

	if(argc != 3) {
        	printf("Usage: hostname  username:pwd\n");
        	exit(1);
    	}

/* get the host info */
	if((serverHost=gethostbyname(argv[1])) == NULL) {
        	herror("gethostbyname(): ");
       		exit(1);
    	}
	ip = inet_ntoa(*((struct in_addr *)serverHost->h_addr));

	launchtcp(ip, argv[1],argv[2]);

}
