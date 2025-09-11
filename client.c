
//TCP Echo Client Pragram

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netdb.h>

#define PSSWRD "theyarewatching123"

struct sockaddr_in serv_addr;

int skfd, r, w;

unsigned short serv_port; 
char serv_ip[20];// = "127.0.0.1"; //152.67.7.144: cloudboot


char rbuff[128];	//stores strings received frm server
char sbuff[128];	//stores wtv client inputs

int main(int argc, char *argv[]) {
	bzero(&serv_addr, sizeof(serv_addr));
	
	printf("Enter Server IP:");
	scanf("%s",serv_ip);

	printf("Enter Server Port: ");
	scanf("%hu",&serv_port);

	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(serv_port);
	inet_aton(serv_ip, (&serv_addr.sin_addr));

	printf("<TCP CHAT CLEINT>\n");

	if((skfd=socket(AF_INET, SOCK_STREAM,0))<0)
	{
		printf("CLIENT ERROR cannot create socket");
		exit(1);
	}
	

	if((connect(skfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))<0)
	{
		printf("%d\n",skfd);
		printf("Client Error: connect to server");
		close(skfd);
		exit(1);
	}
	printf("CLIENT connected to server\n");
	
	//initiate password authentication
	printf("\033[0;33mEnter password: \033[0m ");
	scanf("%s",sbuff);
	
	if(w=write(skfd, sbuff, 128)<0) {
		printf("CLIENT ERROR: Cannot send password to server\n");
		close(skfd);
		exit(1);
	}
	
	if(r=read(skfd,rbuff,128)<0) {
		printf("CLIENT ERROR: Cannot read auth response\n");
		close(skfd);
		exit(1);
	}
	rbuff[strlen(rbuff)]='\0';
	if(strncmp(rbuff,"OK",2)!=0) {
		printf("AUTH FAILED! CLOSING CONNECTION...\n");
		close(skfd);
		exit(1);
	}
	
	printf("\a\033[0;32mAUTHENTICATION SUCCESSFUL!\033[0m\n");
	do{		//Chat Loop
	
		printf("Enter your message: ");	
		scanf(" %[^\n]s",sbuff);
			
		if((w=write(skfd, sbuff, 128))<0) 
		{
			printf("CLIENT Error: cannot send msg to echo server");
			close(skfd);
			exit(1);		
		}
		if(strcmp(sbuff,"STOP")==0) {
			printf("Stop command received, Terminating chat...\n");
			break;
		}
		
		if((r=read(skfd,rbuff,128))<0)
			printf("CLIENT ERROR cannot reveice mssg frm server");
		else {
			rbuff[r]='\0';
			printf("\aServer '%s' says:\033[0;36\6m %s\033[0m\n",inet_ntoa(serv_addr.sin_addr),rbuff);
			if(strcmp(rbuff,"STOP")==0) {
				printf("Stop command received, Terminating chat...\n");			
				break;
			}
		}	
	}while(1);
	close(skfd);
	exit(1);
}
