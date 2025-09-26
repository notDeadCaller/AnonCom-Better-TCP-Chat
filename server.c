//TCP Chat Server Program

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<unistd.h>
#include<math.h>
#include <stdatomic.h>
#include <ctype.h>

#define PSSWRD "theyarewatching123"
#define GOLDENKEY "DontForgetTheGoldenKey123$"
#define MAX_ALLOWED 20   //max IPs in whiteleist
char *allowed_ips[MAX_ALLOWED];//string to store whitelist client IPs
int allowed_count=0;
int goldenKeyFlag=0;
atomic_int waiting = 0;

struct sockaddr_in serv_addr, cli_addr;

int listenfd, connfd, r, w,val, cli_addr_len;
const int sizeFail=5, sizeOk=3;

unsigned short serv_port=25020;
char serv_ip[]="0.0.0.0";
char buff[128];	//stores received strings
char rbuff[128];
//functions
void getAllowlist(const char *fP);
int isAllowed(const char *clientIP);
void* startWaitAnim(void *arg);
long dhexchange();
char *digitsToLetters( long number);
int reverseDigits(int num);
char *vigenereDe(const char *cipher, const char *key);
char *vigenereEn(char plain[128],char key[11]);
long modexp(long base, long exp, long mod) {
    long result=1;
    base %= mod;
    while (exp>0) {
        if (exp&1) result=(result*base)%mod;
        exp>>=1;
        base=(base*base)%mod;
    }  return result;
}


int main() {

	printf("<TCP CHAT SERVER>\n");
	pthread_t tid;

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
		atomic_store(&waiting, 1);
		pthread_create(&tid, NULL,startWaitAnim, NULL);

		if((connfd=accept(listenfd, (struct sockaddr*)&cli_addr,&cli_addr_len))<0)
		{

			printf("SERVER ERROR cannot accept client coonections\n");
			close(listenfd);
			exit(1);
		}
		atomic_store(&waiting, 0);
		pthread_join(tid, NULL);

		char client_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));

		//RUDIMENTARY CONNECTION ESTABLISHED
		printf("SERVER connection from client %s received\n",inet_ntoa(cli_addr.sin_addr));


	//Initiate Password Auth
		r=read(connfd,buff,128);	//read password/goldkey
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
				printf("\033[0;31mSERVER: Wrong password from client %s\033[0m\n",inet_ntoa(cli_addr.sin_addr));
				write(connfd,"FAIL",sizeFail);
				close(connfd);
				continue;
			} else if (!isAllowed(client_ip)) { //if not allowlisted,
			    printf("\a\033[0;31mConnection from %s REJECTED (not in allowlist)\033[0m\n", client_ip);
			    close(connfd);
			    continue;
			}

		}

		const long key=dhexchange();
		if (key == 0) { // Check if the exchange failed
			//printf("Server: Diffie-Hellman exchange failed.\n");
			close(connfd);
			continue;
		}

		write(connfd,"OK",sizeOk);
		printf("SERVER: \033[0;32mAUTHENTICATION SUCCESSFUL for %s\033[0m\n",inet_ntoa(cli_addr.sin_addr));

		fflush(stdout);

		//TODO: do DH exchange & encrypt before chat
		char *charKey=digitsToLetters(key);
		printf("Server key: %ld --> %s\n", key,charKey);

		do{	//Chat Loop
			atomic_store(&waiting, 1);
			pthread_create(&tid, NULL,startWaitAnim, NULL);
			if((r=read(connfd,buff,128))<0)
				printf("SERVER ERROR cannot receive message frm clinet\n");
			else
			{
				char *temp=vigenereDe(buff,charKey);	//decrypt incoming msg
				strcpy(buff,temp);

				atomic_store(&waiting, 0);
				pthread_join(tid, NULL);
				buff[r]='\0';

				if(strcmp(buff,"STOP")==0) {
					printf("Stop command received, Terminating chat...\n");
					break;
				}
				printf("\aClient '%s' says:\033[0;36m %s\033[0m\n",inet_ntoa(cli_addr.sin_addr),buff);


				printf("Enter your message: ");
				scanf(" %[^\n]s",rbuff);
				temp=vigenereEn(rbuff,charKey);
				strcpy(rbuff,temp);

				if((w=write(connfd,rbuff,128))<0)
					printf("SERVER ERROR Cannot send message\n");
				char stopStr[128]="STOP";
				stopStr[128]='\0';
				temp=vigenereEn(stopStr,charKey);
				if(strcmp(rbuff,temp)==0) {
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

void* startWaitAnim(void *arg) {
	const char *rotate[] = {"|", "/", "-", "\\"};
	int i=0;
    while (atomic_load(&waiting)) {
    	//pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        printf("%s", rotate[i]);
        fflush(stdout);
        i = (i + 1)%4;
        usleep(200000); // 300 ms
        printf("\r \r");
        fflush(stdout);
    }
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    printf("\r                             \r"); //take cursor to start, print bigass space, then again to start
    fflush(stdout);
    return NULL;
}

long dhexchange() {
	srand(time(NULL) ^ getpid());
	const long y=rand() % 900000 + 100000;
	const long base=5,mod=99999941;
	long r2;
	send(connfd, &base, sizeof(base), 0);
	send(connfd, &mod, sizeof(mod), 0);
	long r1=modexp(base,y,mod);
	send(connfd, &r1, sizeof(r1), 0);
	if (recv(connfd, &r2, sizeof(r2), 0) != sizeof(r2)) {
	    //perror("recv r2");
	    close(connfd);
	    return 0;
	}
	return modexp(r2, y, mod);
}


char *digitsToLetters( long number) {
    char numstr[11];	//time wont be more than 10
    snprintf(numstr, sizeof(numstr), "%ld", number);

    size_t len = strlen(numstr);
    char *result = malloc(len + 1); // +1 for null terminator
    if (!result) return NULL;
    for (size_t i=0;i<len;i++) {
        if (isdigit((unsigned char)numstr[i])) {
            int digit = numstr[i] - '0';        // 0–9
            result[i] = 'A' + digit;            // A–J
        }
    }
    result[len]='\0';
    return result;
}

int reverseDigits(int num) {
    int rev_num = 0;
    while (num > 0) {
        rev_num = rev_num * 10 + num % 10;
        num = num / 10;
    }    return rev_num;
}


char *vigenereDe(const char *cipher, const char *key) {
    size_t clen=strlen(cipher);
    size_t klen=strlen(key);
    if (klen==0) return NULL;
    char *plain=malloc(clen+1);
    if (!plain) return NULL;

    char *upkey = malloc(klen + 1);	//key always in upper
    if (!upkey) {
        free(plain);
        return NULL;
    }
    for (size_t i=0; i<klen;i++)
        upkey[i]=toupper((unsigned char)key[i]);
    upkey[klen]='\0';

    size_t kpos=0; // position in key (only advances on letters)

    for (size_t i = 0; i < clen; i++) {
        unsigned char c = (unsigned char)cipher[i];
        if (!isalpha(c)) {	//spcl. char. stay as is
            plain[i] = c;
            continue;
        }
        // Determine alphabet base and index
        int base=isupper(c) ? 'A' : 'a';
        int ci=c-base; // cipher index 0–25
        int ki=upkey[kpos % klen] - 'A';
        int pi=(ci - ki + 26) % 26;
        plain[i]=pi+base; // preserve case
        kpos++; // advance key index only for letters
    }
    plain[clen] = '\0';
    free(upkey);
    return plain;
}


char *vigenereEn(char plain[128],char key[11]) {
	int i,counter=0,keyLen,ki,pi;
	static char cipher[128];
	const int temp=strlen(plain);
	char newKey[temp+1],c;
	newKey[temp+1]='\0';
	keyLen=strlen(key);

	for(i=0;i<temp;++i) {	//generate keystream of same length as plaintext
		if(counter>=keyLen)
			counter=0;
		newKey[i]=key[counter];
		counter++;
	}
	newKey[temp]='\0';
	//printf("newkey: %s\n",newKey);	//TEST

	int kpos=0; // position in key::VERI CURCIAL::
	for (i=0;i<temp;i++) {
	    c=plain[i];
	    if (isalpha((unsigned char)c)) {
			pi=tolower(c) - 'a'; // or 'A'
			ki=toupper(key[kpos % keyLen]) - 'A';
			char enc=((pi + ki) % 26) + 'a'; // or 'A'
			cipher[i] = isupper(c) ? toupper(enc) : enc;
			kpos++; // advance key only when we used it
	    } else	cipher[i] = c;
	}
	cipher[temp]='\0';
	//printf("Cipher: %s\n",cipher);
	return cipher;
}
