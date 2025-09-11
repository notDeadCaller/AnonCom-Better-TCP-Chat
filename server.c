//TCP Client Server Program

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define PSSWRD "theyarewatching123"
#define GOLDENKEY "DontForgetTheGoldenKey123$"
#define MAX_ALLOWED 20   //max IPs in whiteleist
char *allowed_ips[MAX_ALLOWED];//string to store whitelist client IPs
int allowed_count=0;
int goldenKeyFlag=0;

struct sockaddr_in serv_addr, cli_addr;

int listenfd, connfd, r, w,val, cli_addr_len;
const int sizeFail=5, sizeOk=3;

unsigned short serv_port=25020;
char serv_ip[]="0.0.0.0";
char buff[128];	//stores received strings
char rbuff[128];

void getAllowlist(const char *fP);
int isAllowed(const char *clientIP);

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
	
	getAllowlist("firewall.conf");	

	cli_addr_len=sizeof(cli_addr);
	for(; ;)
	{
		printf("SERVER Listening for clients\n");
		if((connfd=accept(listenfd, (struct sockaddr*)&cli_addr,&cli_addr_len))<0)
		{
			printf("SERVER ERROR cannot accept client coonections\n");
			close(listenfd);
			exit(1);
		}
		char client_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
		
		printf("SERVER connection from client %s received\n",inet_ntoa(cli_addr.sin_addr));
		
	//Initiate Password Auth	
		r=read(connfd,buff,128);	
		if(r<0) {
    			printf("SERVER Error: no password received\n");
    			close(connfd);
    			continue;
		}
		buff[r]='\0';
		if(strcmp(buff,GOLDENKEY)==0) {//if golden access key entered, skip authentication
			goldenKeyFlag=1;
			printf("***Golden Key ACTIVATED***\n");
		}
			
		if(goldenKeyFlag!=1) {
			
			if(strcmp(buff,PSSWRD)!=0) {
				printf("SERVER: Wrong password from client %s\n",inet_ntoa(cli_addr.sin_addr));
				write(connfd,"FAIL",sizeFail);	
				close(connfd);
				continue;
			} else if (!isAllowed(client_ip)) { //if not allowlisted,
			    printf("\a\033[0;31mConnection from %s REJECTED (not in allowlist)\033[0m\n", client_ip);
			    close(connfd);
			    continue;		
			}
		}
			write(connfd,"OK",sizeOk);	
			printf("SERVER: \033[0;32mAUTHENTICATION SUCCESSFUL for %s\033[0m\n",inet_ntoa(cli_addr.sin_addr));
		
		
		
		
		do{	//Chat Loop
		if((r=read(connfd,buff,128))<0)
			printf("SERVER ERROR cannot receive message frm clinet\n");
		else 
		{
			buff[r]='\0';
			
			if(strcmp(buff,"STOP")==0) {
				printf("Stop command received, Terminating chat...\n");			
				break;
			}
			printf("\aClient '%s' says:\033[0;36m %s\033[0m\n",inet_ntoa(cli_addr.sin_addr),buff);
			
				
			printf("Enter your message: ");
			scanf(" %[^\n]s",rbuff);
			
			if((w=write(connfd,rbuff,128))<0)
				printf("SERVER ERROR Cannot send message\n");	
				
			if(strcmp(rbuff,"STOP")==0) {
				printf("Stop command received, Terminating chat...\n");			
				break;
			}		
		}
		}while(1);	

	}
}

void getAllowlist(const char *firewall) {
    FILE *fP = fopen(firewall, "r");
    if (!fP) {
        perror("Could not open firewall.conf");
        exit(1);
    }

    char line[INET_ADDRSTRLEN];
    while (fgets(line, sizeof(line),fP)) {
        // remove newline
        line[strcspn(line, "\r\n")]=0;
        if (strlen(line)>0 && allowed_count<MAX_ALLOWED) {
            allowed_ips[allowed_count]=strdup(line);
            allowed_count++;
        }
    }
    fclose(fP);
    printf("Loaded %d allowed IP(s) from %s\n", allowed_count, firewall);
}

int isAllowed(const char *clientIP) {
    for (int i=0;i<allowed_count;i++) {
        if (strcmp(clientIP, allowed_ips[i])==0) {
            return 1; // match found
        }
    }
    return 0; // not allowed
}
