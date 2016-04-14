#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <net/if.h>
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


#define PERROR(x) do { perror(x); exit(1); } while (0)
#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh !";


void usage()
{
        fprintf(stderr, "Usage: server [-s port|]\n");
        exit(0);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{
   /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */
	struct ifreq ifr;
	int fd, err;

/*open the device*/

	if((fd = open("/dev/net/tun", O_RDWR)) < 0){
		perror("Open /dev/net/tun error");
		return fd;
	}
///* preparation of the struct ifr, of type "struct ifreq" */

	memset(&ifr, 0, sizeof(ifr));
	
	ifr.ifr_flags = flags; //IFF_TUN or IFF TAP

	
	if(*dev)
	{
		/* if a device name was specified, put it in the structure; otherwise,
     		 * the kernel will try to allocate the "next" device of the
      		* specified type */
     		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
	
	//try to create the device
	if((err = ioctl(fd, TUNSETIFF,(void *) &ifr)) < 0){
		perror("ioctl(TUNSETIFF) error");		
		close(fd);
		return err;
	}
	
	strcpy(dev, ifr.ifr_name); // write back the name of the interface to dev
	return fd;
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
        fd_set fdset;

        int MODE = 0, TUNMODE = IFF_TUN, DEBUG = 0;

        while ((c = getopt(argc, argv, "s:c:ehd")) != -1) {
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
                case 'c':
                        MODE = 2;
                        p = memchr(optarg,':',16);
                        if (!p) ERROR("invalid argument : [%s]\n",optarg);
                        *p = 0;
                        ip = optarg;
                        port = atoi(p+1);
                        PORT = 0;
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
			l = read(fd, buf, sizeof(buf));
			if(l < 0) PERROR("read");
			if(sendto(s, buf, l, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
			
		}
		if(FD_ISSET(s, &fdset)){
			if(DEBUG) write(1,"<",1);
			l = recvfrom(s, buf, sizeof(buf),0,(struct sockaddr *)&sout, &soutlen);
			if((sout.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
				 printf("Got packet from  %s:%i instead of %s:%i\n",
                                       inet_ntoa(sout.sin_addr), ntohs(sout.sin_port),
                                       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                        if (write(fd, buf, l) < 0) PERROR("write");
		}
		
	}

}
