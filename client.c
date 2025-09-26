
//TCP Chat Client Pragram

#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netdb.h>
#include<pthread.h>
#include<unistd.h>
#include<stdatomic.h>
#include<string.h>
#include<math.h>
#include<ctype.h>

struct sockaddr_in serv_addr;

int skfd, r, w;
atomic_int waiting = 0;
unsigned short serv_port; 
char serv_ip[20];// = "127.0.0.1"; //152.67.7.144: cloudboot

char rbuff[128];	//stores strings received frm server
char sbuff[128];	//stores wtv client inputs

void* startWaitAnim(void *arg);
char *digitsToLetters( long number);
int reverseDigits(int num);
char *vigenereDe(const char *cipher, const char *key);
char *vigenereEn(char plain[128],char key[11]);
long dhexchange();
long modexp(long base, long exp, long mod) {
    long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}


int main(int argc, char *argv[]) {

	pthread_t tid;
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
	
	if(w=write(skfd, sbuff, 28)<0) {		//send password/goldkey
		printf("CLIENT ERROR: Cannot send password to server\n");
		close(skfd);
		exit(1);
	}
	const long key = dhexchange();
	if (key == 0) { // Check if the exchange failed
		//printf("Client: Diffie-Hellman exchange failed.\n");
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
		printf("\033[0;31mAUTH FAILED! CLOSING CONNECTION...\033[0m\n");
		close(skfd);
		exit(1);
	}
	printf("\a\033[0;32mAUTHENTICATION SUCCESSFUL!\033[0m\n");
	fflush(stdout);

	char *charKey=digitsToLetters(key);
	printf("Client key: %ld --> %s\n", key,charKey);	
	
	do{		//Chat Loop
		printf("Enter your message: ");	
		scanf(" %[^\n]s",sbuff);
		char *temp=vigenereEn(sbuff,charKey);
		strcpy(sbuff,temp);
		
		if((w=write(skfd, sbuff, 128))<0) 
		{
			printf("CLIENT Error: cannot send msg to echo server");
			close(skfd);
			exit(1);		
		}
		char stopStr[128]="STOP";
		stopStr[128]='\0';
		temp=vigenereEn(stopStr,charKey);
		if(strcmp(sbuff,temp)==0) {	//check if STOP entered by client
			printf("Stop command received, Terminating chat...\n");
			break;
		}
		atomic_store(&waiting, 1);
		pthread_create(&tid, NULL,startWaitAnim, NULL);
		if((r=read(skfd,rbuff,128))<0)
			printf("CLIENT ERROR cannot reveice mssg frm server");
		else {
			temp=vigenereDe(rbuff,charKey);	//decrypt incoming msg
			strcpy(rbuff,temp);
			atomic_store(&waiting, 0);
			pthread_join(tid, NULL);	
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
	const long y2=rand() % 900000 + 100000;
	long base,mod,r1;
	recv(skfd, &base, sizeof(base), 0);
	recv(skfd, &mod, sizeof(mod), 0);
	if (recv(skfd, &r1, sizeof(r1), 0) != sizeof(r1)) {
	    //perror("recv r1");
	    close(skfd);
	    return 0;
	}
	long r2=modexp(base,y2,mod);
	send(skfd, &r2, sizeof(r2), 0);
	
	return modexp(r1, y2, mod);
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
