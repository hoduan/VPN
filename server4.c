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
#include <sys/wait.h>
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
#define KEY_LEN 16
#define SHA256_LEN 32
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
	unsigned char *user, *pwd,*tmppwd,*record_u,*record_p;	
	unsigned char phash[32];
	unsigned char hash[64];
	char tmp[BUFSIZE];
	int i;
	unsigned char *salt;
	user = malloc(12);
	pwd = malloc(30);
	tmppwd = malloc(30+2*KEY_LEN);
	record_u = malloc(12);
	record_p = malloc(30);
	salt = malloc(2*KEY_LEN);
	
	user = strtok(msg, ":");
	pwd = strtok(NULL,":");
	

	FILE *f;
	size_t len;
	char* line;
	f = fopen("data.txt", "r");
	if(f == NULL) {perror("the data file is null, nothing stored there!"); return 0;}

	while((getline(&line,&len,f))!=-1)
	{
		record_u = strtok(line,":");
		if(memcmp(user,record_u,strlen(user)) == 0 && (strlen(user) == strlen(record_u)))
		{
			salt = strtok(NULL,":");
			memcpy(tmppwd,salt,2*KEY_LEN);
			memcpy(tmppwd+2*KEY_LEN,pwd,30);	
			gethash(tmppwd,phash);
			for(i=0;i<32;i++)sprintf(hash+i*2,"%02x",phash[i]);
			record_p =strtok(NULL,":");
			if(memcmp(hash,record_p,2*SHA256_LEN) == 0)
			{
				printf("\nAuthorization checking passed!\n");
				return 1;
			}
		
	
				
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
				for(index=0;index<16;index++)printf("%02x",key[index]);

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
		
		memset(buf,0,BUFSIZE);
		unsigned char *code;
		char buftemp[BUFSIZE];
		int fds[2];
		unsigned char *newkey = malloc(KEY_LEN);
		pid_t childpid;
		int status;
		pipe2(fds,O_NONBLOCK);
		childpid = fork();
		
		////////////////////////////////////////////////////////////////////////////
		//UDP Data Tunnel
		if(childpid == 0)
		{
			struct sockaddr_in usaddr, sout, from;
			struct ifreq ifr;
			int fd, s, fromlen, soutlen, mlen;
			char buffer[BUFSIZE];
			unsigned char *plainbuf, *cryptbuf, *hmacbuf, *tmpbuf;
			unsigned char *iv, *tmpkey;
			int plainlen, cryptlen, nbytes;
			fd_set fdset;

			int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 1;

			plainbuf = malloc(BUFSIZE);
			cryptbuf = malloc(BUFSIZE);
			hmacbuf = malloc(BUFSIZE);
			tmpbuf = malloc(BUFSIZE);
			iv = malloc(KEY_LEN);
			tmpkey = malloc(KEY_LEN);
			memcpy(newkey, key, KEY_LEN);
	

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
	
			memset(&usaddr,0,sizeof(usaddr));
			usaddr.sin_family = AF_INET;
			usaddr.sin_addr.s_addr = htonl(INADDR_ANY);
			usaddr.sin_port = htons(UDP_PORT);
			if ( bind(s,(struct sockaddr *)&usaddr, sizeof(usaddr)) < 0) PERROR("bind");
	
			memcpy(&from,&caddr,sizeof(caddr));
			from.sin_port = htons(UDP_PORT);
			fromlen = sizeof(from);

			//////////////////////////////////////////////////////////////////////////////////////////////////
			//Send and receive packets	
			while(1)
			{
				FD_ZERO(&fdset);
				FD_SET(fd, &fdset);
				FD_SET(fds[0],&fdset);
				FD_SET(s, &fdset);
				if(select(fd+fds[0]+s+1, &fdset, NULL, NULL, NULL) < 0) PERROR("select");
		
				if(FD_ISSET(fds[0],&fdset))
				{
					close(fds[1]);
					nbytes = read(fds[0], tmpkey, KEY_LEN);
					if(nbytes!=-1 && nbytes != 0)
					{
						//update key
						if(nbytes == 16)memcpy(newkey, tmpkey, KEY_LEN);
					
						//close connection
						if(nbytes == 1)
						{	
							memset(key,0,KEY_LEN);
							memset(newkey,0,KEY_LEN);
							memset(tmpkey,0,KEY_LEN);
							memset(buffer,0,BUFSIZE);
							close(fd);
							close(s);
							exit(0);
						}
					}
				}
	

				if(FD_ISSET(fd, &fdset))
				{
					if(DEBUG) write (1,">",1);
					mlen = iread(fd, buffer, sizeof(buffer));
					if( mlen != -1)
					{       //do encryption
						iv = getkey();
						cryptlen = do_crypt(newkey, iv, buffer, mlen, cryptbuf, 1);
						memcpy(tmpbuf,iv,KEY_LEN);
						memcpy(tmpbuf+KEY_LEN, cryptbuf, cryptlen);

						//hmac inclued iv + encrypted data
						do_hmac(newkey,tmpbuf,KEY_LEN+cryptlen,hmacbuf);

						//copy iv, encrypted data and hmac into buffer and then send
						memcpy(buffer, iv, KEY_LEN);
						memcpy(buffer+KEY_LEN, cryptbuf, cryptlen);
						memcpy(buffer+KEY_LEN+cryptlen, hmacbuf, SHA256_LEN);
						int buflen = KEY_LEN + cryptlen + SHA256_LEN;

						if(sendto(s, buffer, buflen, 0, (struct sockaddr *)&from, fromlen) < 0)
								PERROR("send to");
					}
				}
				if(FD_ISSET(s, &fdset))
				{
					if(DEBUG) write(1,"<",1);
					mlen = recvfrom(s, buffer, sizeof(buffer),0,(struct sockaddr *)&sout, &soutlen);
                    			memcpy(cryptbuf, buffer, mlen-SHA256_LEN);
                			memcpy(iv, buffer, KEY_LEN);
                			// do hmac to check the signature, if matches, decrypt the data
               				do_hmac(key,cryptbuf,mlen-SHA256_LEN,hmacbuf);
					if(memcmp(hmacbuf,buffer+mlen-SHA256_LEN, SHA256_LEN) !=0 && memcmp(key, newkey, KEY_LEN)!=0)
					{
						memcpy(key, newkey, KEY_LEN);
						do_hmac(key,cryptbuf,mlen-SHA256_LEN,hmacbuf);
						printf("\nupdated key in server:");
                               			for(i=0;i<16;i++)printf("%02x",key[i]);
					}
                			if (memcmp(hmacbuf, buffer+mlen-SHA256_LEN, SHA256_LEN) == 0 && mlen!= -1)
                			{
                        			//do decryption, need to exclude iv and hmac
                        			plainlen = do_crypt(key, iv,cryptbuf+KEY_LEN,mlen-KEY_LEN-SHA256_LEN, plainbuf, 0);
                        			iwrite(fd, plainbuf, plainlen);
                			}
               				else
					{
                        			printf("ERROR, message check failed.\n");
                        			printf("message length: %d\n", mlen);
                			}

				}	
			}
		exit(EXIT_SUCCESS);

	}
	
	else if(childpid > 0)
	{	
		memset(key,0,KEY_LEN);
		memset(newkey,0,KEY_LEN);
		
		while(1)
		{
			l = SSL_read(ssl, buf, BUFSIZE);
			if(l > 0)
			{	memcpy(buftemp, buf, l);	
				code = strtok(buftemp, ":");
				// change key
				if(memcmp(code, "1",1) == 0)
				{
					close(fds[0]);
					write(fds[1],buf+2, KEY_LEN);
				
				}

				//close connection
				if(memcmp(code, "0",1) == 0){
					close(fds[0]);
					write(fds[1],buf,1);
					close(client_fd);
					memset(buf,0,BUFSIZE);
				//wait for child process to exit
					wait(&status);
					exit(0);
				}
			}
			else {close(client_fd); exit(1);}
		}
		exit(EXIT_SUCCESS);

	}
	else {perror("fork udp tunnle error");exit(EXIT_FAILURE);}
}

int main(int argc, char *argv[])
{

launchtcp();

return 0;

}
