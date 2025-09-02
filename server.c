//TCP Echo Server Program

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define PSSWRD "TEST"

struct sockaddr_in serv_addr, cli_addr;

int listenfd, connfd, r, w,val, cli_addr_len;

unsigned short serv_port=25020;
char serv_ip[]="0.0.0.0";

char buff[128];	//stores received strings
char rbuff[128];

int main() {

	printf("CHAT SERVER\n");

	if((listenfd=socket(AF_INET, SOCK_STREAM, 0))<0)
	{
		printf("\nserver error: cannot create socket!\n");
		exit(1);
	}

	bzero(&serv_addr, sizeof(serv_addr));

	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(serv_port);
	inet_aton(serv_ip, (&serv_addr.sin_addr));


	if((bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))<0)
	{
		printf("\nSERVER ERROR: cannot bind");
		close(listenfd);
		exit(1);
	}

	if((listen(listenfd, 5))<0)
	{
		printf("\nSERVER ERROR cannot listen");
		close(listenfd);
		exit(1);
	}




	cli_addr_len=sizeof(cli_addr);
	for(; ;)
	{
		printf("SERVER Listening for clients\n");
		if((connfd=accept(listenfd, (struct sockaddr*)&cli_addr,&cli_addr_len))<0)
		{
			printf("SERVER ERROR cannot accept client coonections");
			close(listenfd);
			exit(1);
		}
		printf("SERVER connection from client %s ccepted\n",inet_ntoa(cli_addr.sin_addr));

	//Initiate Password Auth
		r=read(connfd,buff,128);
		if(r<0) {
    			printf("SERVER Error: no password received\n");
    			close(connfd);
    			continue;
		}
		buff[r]='\0';
		if(strcmp(buff,PSSWRD)!=0) {
			printf("SERVER: Wrong password from client %s\n",inet_ntoa(cli_addr.sin_addr));
			write(connfd,"FAIL",128);
			close(connfd);
			continue;
		} else {
			write(connfd,"OK",128);
			printf("SERVER: Auth success for client %s\n",inet_ntoa(cli_addr.sin_addr));
		}

		do{	//Chat Loop
		if((r=read(connfd,buff,128))<0)
			printf("SERVER ERROR cannot receive message frm clinet");
		else
		{
			printf("r:%d\n",r);
			buff[r]='\0';

			if(strcmp(buff,"STOP")==0) {
				printf("Stop command received, Terminating chat...\n");
				break;
			}
			printf("Client '%s' says : %s\n",inet_ntoa(cli_addr.sin_addr),buff);

			printf("Enter your message: ");
			scanf("%s",rbuff);

			if((w=write(connfd,rbuff,128))<0)
				printf("SERVER ERROR Cannot send message");

			if(strcmp(rbuff,"STOP")==0) {
				printf("Stop command received, Terminating chat...\n");
				break;
			}
		}
		}while(1);

	}
}