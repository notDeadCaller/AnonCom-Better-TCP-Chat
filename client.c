
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
#include<string.h>
#include<math.h>
#include<ctype.h>
#include<time.h>
#include<ncurses.h>

struct sockaddr_in serv_addr;

int skfd, r, w;
unsigned short serv_port; 
char serv_ip[20];// = "127.0.0.1"; //152.67.7.144: cloudboot
WINDOW *input_win;		//ncurses window thingy
pthread_mutex_t screen_mutex;		//ncurses Window thread
pthread_t send_thread, recv_thread;	//chat thread

char rbuff[128];	//stores strings received frm server
char sbuff[128];	//stores wtv client inputs

void* getMessages(pthread_t tid, int skfd, char rbuff[128], char *key, int r);
void *send_handler(void *arg);
void *receive_handler(void *arg);
char *digitsToLetters( long number);
int reverseDigits(int num);
char *vigenereDe(const char *cipher, const char *key);
char *vigenereEn(char plain[128],char key[11]);
long dhexchange();
void measure_latency(int sockfd);
long modexp(long base, long exp, long mod) {
    long result=1;
    base%=mod;
    while (exp>0) {
        if (exp&1) result=(result*base)%mod;
        exp>>=1;
        base=(base*base)%mod;
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
	const long key=dhexchange();
	if (key==0) { // Check if the exchange failed
		printf("Client: Diffie-Hellman exchange failed.\n");
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
	
	measure_latency(skfd);		//measure and display ping

	char *charKey=digitsToLetters(key);
	printf("Client key: %ld --> %s\n", key,charKey);	//key for the session
	r=read(skfd,rbuff,128);		//read message of day frm server
	rbuff[r]='\0';
	printf("Message of the day is:  %s",rbuff);
	
	printf("\n:::Type \033[0;31m'STOP'\033[0m to end the connection:::\n");	//chat threads
	sleep(2);//2sec delay
	initscr();
	start_color();
    	cbreak();	//---BEGIN NCURSES MODE---
    
	int height, width;
    	getmaxyx(stdscr, height, width);
    	scrollok(stdscr, TRUE);	//enable scrolling thru chat
    	// Clear the main screen before we start
    	clear();
    	refresh();

    	// Create a 1-line-high window at the bottom of the screen for input
   	input_win = newwin(1, width, height - 1, 0);
    
    	pthread_mutex_init(&screen_mutex, NULL);

    	wprintw(stdscr, "--- Chat Session Started ---\n");
    	wrefresh(stdscr);

	// Initialize the mutex
	pthread_mutex_init(&screen_mutex, NULL);

	if (pthread_create(&send_thread, NULL, send_handler, NULL) != 0) {
		perror("Failed to create send thread");
        	close(skfd);
		exit(1);
	}
	if (pthread_create(&recv_thread, NULL, receive_handler, NULL) != 0) {
		perror("Failed to create receive thread");
		pthread_cancel(send_thread);
        	close(skfd);
		exit(1);
	}

	pthread_join(send_thread, NULL);
	pthread_join(recv_thread, NULL);
	getmaxyx(stdscr, height, width);
	char line_buffer[width + 1];	//store last few lines of chat history
	pthread_mutex_destroy(&screen_mutex);
	endwin();
	for (int i = 0; i < height - 1; i++) {
		mvwinnstr(stdscr, i, 0, line_buffer, width);
		char *end = line_buffer + strlen(line_buffer) - 1;
		 while (end >= line_buffer && isspace((unsigned char)*end)) end--;
		*(end + 1) = '\0';
		if (strlen(line_buffer) > 0) 
		printf("%s\n", line_buffer);
	}
    	printf("---------------------------\n");
	close(skfd);
	exit(1);
}

void *send_handler(void *arg) {
    char sbuff[128];
    char prompt[] = "> ";

    while (1) {
        wgetstr(input_win, sbuff);
        pthread_mutex_lock(&screen_mutex);
        wprintw(stdscr, "%s%s\n", prompt, sbuff);
        wclear(input_win);	//clear the typing line once msg is sent
        wnoutrefresh(stdscr);	//"harder, virtual" refresh function than just wrefresh      
        wnoutrefresh(input_win);
        doupdate();		//"harder" update

        pthread_mutex_unlock(&screen_mutex);
        if (write(skfd, sbuff, strlen(sbuff)) < 0) break;
        if (strcmp(sbuff, "STOP") == 0) break;
    }
    pthread_cancel(recv_thread);
    pthread_exit(NULL);
}

void *receive_handler(void *arg) {
    char rbuff[128];
    int bytes_read;

    while (1) 
    {    
        bytes_read = read(skfd,rbuff,sizeof(rbuff)-1);
        if (bytes_read <= 0) //if nothing received
            break;
        rbuff[bytes_read] = '\0';   
	init_pair(1, COLOR_CYAN, COLOR_BLACK);             
        pthread_mutex_lock(&screen_mutex);
        attron(COLOR_PAIR(1));
        wprintw(stdscr, "Server says: %s\n", rbuff);   
        attroff(COLOR_PAIR(1));     
        wnoutrefresh(stdscr);		//"harder, virtual" refresh function than just wrefresh        
        wnoutrefresh(input_win);	//prevent the input bar from disappearing half cooked way
        doupdate();			//"harder" update
        
        pthread_mutex_unlock(&screen_mutex);
        if (strcmp(rbuff, "STOP") == 0) break;
    }
    pthread_cancel(send_thread);
    pthread_exit(NULL);
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
	return cipher;
}


void measure_latency(int sockfd) {
    const char *ping_msg="LATENCY_PING";
    char buffer[32];
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    write(sockfd, ping_msg, strlen(ping_msg));

    read(sockfd, buffer, sizeof(buffer) - 1);

    clock_gettime(CLOCK_MONOTONIC, &end);

    double rtt_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf("Connection Latency (RTT):\033[0;32m %.2f ms\033[0m\n", rtt_ms);
}
