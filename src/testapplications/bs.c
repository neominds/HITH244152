/* includes */

#include "vxWorks.h"  
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>  
#include "socket.h"  
#include "in.h"  
#include "inetLib.h"
#include "ifLib.h"
  
#define SERVER_PORT_NUM	7001

/***************************************************************************** 
 * bs - Server reads from local socket and displays client's message.  
 * and sends a reply back to the client. Code executes on 
 * VxWorks target and use VxWorks header files. 
 * 
 *  EXAMPLE: 
 * 
 *     To run this bcastServer task, from the VxWorks shell do as follows: 
 *     -> bs 
 * 
 *  RETURNS: OK or ERROR 
 */  
   
STATUS bs(char *bsaddr)  
    {  
    struct sockaddr_in myAddr;      /* Server socket address */  
    struct sockaddr_in clientAddr;  /* Socket address for client */  
    char clientRequest[128];
    int sFd;                /* Server's socket file descriptor */  
    char inetAddr[INET_ADDR_LEN];   /* Buffer for dot notation * 
                                 * internet addr of client */  
  
    /* Size of socket address structure */  
    int sockAddrSize = sizeof (struct sockaddr_in);  
    int msgcount = 1;
    LOCAL char replyMsg[128];
  
    /* Build socket address */  
    bzero ((char *) &myAddr, sockAddrSize);  
    myAddr.sin_family = AF_INET;  
    myAddr.sin_port = htons (SERVER_PORT_NUM);  
    if (!bsaddr || !strcmp(bsaddr,"")) {
    	myAddr.sin_addr.s_addr = htonl (INADDR_ANY);
    }
    else {
    	myAddr.sin_addr.s_addr = inet_addr(bsaddr);
    }
  
    /* Create socket */  
    if ((sFd = socket (AF_INET, SOCK_DGRAM, 0)) == ERROR)  {  
    	perror ("socket");  
    	close (sFd);  
    	return (ERROR);  
    }  
  
    /* Bind socket to local address */  
    if (bind (sFd, (struct sockaddr *) &myAddr, sockAddrSize) == ERROR) {  
        perror ("bind");  
        close (sFd);
        return (ERROR);  
    }  
    printf("Broadcast server listening on port %d\n", ntohs(myAddr.sin_port));
  
    FOREVER {  
    	/* Read data from a socket and satisfy requests */  
    	if (recvfrom (sFd, &clientRequest, sizeof (clientRequest), 0,  
              (struct sockaddr *) &clientAddr,&sockAddrSize) == ERROR) {  
            perror ("recvfrom");  
            close (sFd);  
            return (ERROR);  
        }  
        /* Convert internet address to dot notation for displaying */  
    	inet_ntoa_b (clientAddr.sin_addr, inetAddr);  
    	printf ("<<< [%s:%d]: %s\n",  
        inetAddr, ntohs (clientAddr.sin_port), clientRequest);  
  
    	if (strstr(clientRequest,"-stop bs") != 0) break;
    	
        sprintf(replyMsg,"msg%03d-%s",msgcount++,"reply from bserver");
        if (sendto (sFd, replyMsg, sizeof (replyMsg), 0,   
                        (struct sockaddr *) &clientAddr,sockAddrSize) == ERROR){  
            perror ("sendto");  
            close (sFd);  
            return (ERROR);  
        }
      	printf (">>> [%s:%d]: %s\n", inetAddr, ntohs (clientAddr.sin_port), replyMsg);  
    }  
  
    close (sFd);   
    
    return TRUE;
}
