#include <errno.h>  
#include <stdio.h>  
#include <string.h>
#include <unistd.h>  
#include "vxWorks.h"  
#include "socket.h"  
#include "sockLib.h"  
#include "in.h"
#include "ifLib.h"
#include <arpa/inet.h>  
  
LOCAL char buf[128],usermsg[120];
int msgcount =1;
char bsAddrStr[20];
  
/***************************************************************************** 
 * bc - Sends broadcasting message  
 * 
 * DESCRIPTION 
 * 
 *     Demo for sending broadcasting message. 
 * 
 * RETURNS: OK or ERROR 
 * 
 * 
 * EXAMPLE: 
 * 
 *     Run bc task on VxWorks system as follows 
 * 
 *     -> bc("192.168.200.255", 7001) 
 * 
 *     where 7001 (port number should be greater than 5000 for user-developed) 
 *     is an example port number used in this demonstration to send the 
 *     broadcast message. 
 * 
 */  
  
STATUS bc(char *bsaddr, int port);  
  
STATUS bc   
    (  
    char *bsaddr, int port                             /* IP addr and port number */  
    )  
  
    {  
    int sockFd;                          /* socket fd */  
    struct sockaddr_in sendToAddr;       /* receiver's addresss */  
    int   sendNum ;  
    int   on;
    struct sockaddr_in bsAddr; 
    int bsAddrSize = sizeof (struct sockaddr_in); 
  
  
    /* Open UDP socket */  
    sockFd = socket(AF_INET, SOCK_DGRAM, 0);  
    if (sockFd == ERROR)  
    {   
    perror ("socket not opened ");  
    return (ERROR);  
    }  
  
  
    /* Use the SO_BROADCAST option when an application needs to broadcast data 
     */   
   
    on = 1; /* turn ON SO_BROADCAST option*/  
    if (setsockopt (sockFd, SOL_SOCKET, SO_BROADCAST, (char *) &on, sizeof(int))  ==   
                     ERROR)  
    {  
    perror ("setsockopt BROADCAST failed ");  
    return (ERROR);  
    }  

    /*settimeout for recv */
    struct timeval tm;
    tm.tv_sec = 3 ;
    tm.tv_usec = 0 ;
    
    if (setsockopt (sockFd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tm, sizeof(struct timeval))  ==   
                     ERROR)  
    {  
    perror ("setsockopt RCVTIMEO failed ");  
    return (ERROR);  
    }    
    
    /* zero out the sockaddr_in structures and setup receivers' address */   
    bzero ((char *) &sendToAddr, sizeof (struct sockaddr_in));  
    sendToAddr.sin_family = AF_INET;  
    sendToAddr.sin_port = htons (port);  
    sendToAddr.sin_addr.s_addr = inet_addr (bsaddr);
  
    FOREVER {   	 
    	 printf("Ready>");
    	 gets(usermsg);
    	 if (strcmp(usermsg,"quit") == 0) break;
    	 
    	 sprintf(buf,"msg%03d-%s",msgcount++,usermsg);
    	 
    	 /* send the broadcast message to other systems in the same network */  
    	 if ((sendNum = sendto (sockFd, buf, sizeof (buf), 0, (struct sockaddr  *) &sendToAddr,   
    			 sizeof (struct sockaddr_in))) == ERROR)  {  
    		 	 perror ("sendto broadcast failed ");  
    		 	 return (ERROR);  
    	 	 }  
  
    	 printf (">>> [%s:%d] %s\n",bsaddr,port,buf);
    	 
    	 if (strcmp(usermsg,"stop bs") == 0) break;
    	 
    	 int rcvdbytes;
    	 while (1)
    	 {  		 
    		 rcvdbytes = recvfrom (sockFd, &buf, sizeof (buf), 0,  
                 (struct sockaddr *) &bsAddr,&bsAddrSize);
    		 if (rcvdbytes == ERROR && errno == EWOULDBLOCK) break;
    		 if (rcvdbytes == ERROR) {  
    			 perror ("recvfrom");  
    			 close (sockFd);  
    			 return (ERROR);  
    		 }
     	 
    		 inet_ntoa_b (bsAddr.sin_addr, bsAddrStr); 
    		 printf ("<<< [%s:%d] %s\n",bsAddrStr,ntohs(bsAddr.sin_port), buf);
    	 }
    }
    close (sockFd);  
    return(TRUE);  
}
