//Post Quantum TCP Chat Server Program

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
#include<ncurses.h>
#include<signal.h>
#include <stdatomic.h>
#include <ctype.h>
#include <oqs/oqs.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#define PSSWRD "theyarewatching123"
#define GOLDENKEY "DontForgetTheGoldenKey123$"
#define MAX_ALLOWED 20   //max IPs in whiteleist
#define MAX_CHARGES 10.5      
#define CHARGE_RATE 1.5 

#define IV_LEN 12
#define TAG_LEN 16
#define MSG_BUF_SIZE 256

char *allowed_ips[MAX_ALLOWED];//string to store whitelist client IPs
int allowed_count=0;	//max IPs allowed
int goldenKeyFlag=0;
atomic_int waiting=0;	//monitor for dash animation
double clientCharges = MAX_CHARGES;
uint8_t *shared_secret_bin = NULL;
size_t shared_secret_len = 0;
time_t last_refill_time;
WINDOW *input_win;		//ncurses window thingy
pthread_mutex_t screen_mutex;		//ncurses Window thread
pthread_t send_thread, recv_thread;	//chat threads
volatile sig_atomic_t chat_is_active = 1;

struct sockaddr_in serv_addr, cli_addr;

int listenfd, connfd, r, w,val, cli_addr_len;

unsigned short serv_port=25021;
char serv_ip[]="0.0.0.0";
char buff[128];	//stores received strings
char rbuff[128];
//functions
void getAllowlist(const char *fP);
char *getMessageOfTheDay();
int isAllowed(const char *clientIP);
void* startWaitAnim(void *arg);
void *send_handler(void *arg);
void *receive_handler(void *arg);
int can_send_message();
ssize_t recv_all(int connfd, void *buf, size_t len);
long dhexchange();
char *digitsToLetters( long number);
long modexp(long base, long exp, long mod) {
    long result=1;
    base%=mod;
    while (exp>0) {
        if (exp&1) result=(result*base)%mod;
        exp>>=1;
        base=(base*base)%mod;
    }  return result;
}

uint8_t* kyber_key_exchange_server(int connfd) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return NULL;

    uint8_t *public_key=malloc(kem->length_public_key);
    uint8_t *secret_key=malloc(kem->length_secret_key);
    OQS_KEM_keypair(kem, public_key, secret_key);

    //send the public key
    write(connfd, public_key, kem->length_public_key);

    //wait to receive the ciphertext using our robust helper
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    if (recv_all(connfd, ciphertext, kem->length_ciphertext) < 0) {
        perror("Failed to receive ciphertext");
        return NULL;
    }
    //decapsulate to reveal secret shared key
    uint8_t *shared_secret_bin1 = malloc(kem->length_shared_secret);
    OQS_KEM_decaps(kem,shared_secret_bin1,ciphertext,secret_key);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    //free(shared_secret_bin);
    OQS_KEM_free(kem);

    return shared_secret_bin1; //return as base64 string
}


// Returns the length of the ciphertext. -1 on failure.
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key,
                    unsigned char *iv,        // OUT: 12-byte IV
                    unsigned char *ciphertext, // OUT: ciphertext
                    unsigned char *tag) {      // OUT: 16-byte GCM tag

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // Generate a random IV for each message (CRITICAL for security)
    if(1 != RAND_bytes(iv, 12)) return -1;

    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) return -1;

    // Provide the message to be encrypted, and obtain the encrypted output.
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    // Finalise the encryption.
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    // Get the GCM tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return -1;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
// Returns the length of the plaintext. -1 on failure (e.g., tag mismatch).
int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *tag,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *plaintext) { // OUT: plaintext

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // Initialise the decryption operation.
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) return -1;

    // Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    // Set the expected GCM tag. This is the integrity check.
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) return -1;

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Tag verification failed!
        return -1;
    }
}

int main() {
	const int sizeFail=5, sizeOk=3;
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
		
		//const long key=dhexchange();	
		shared_secret_bin = kyber_key_exchange_server(connfd);
		if (shared_secret_bin == NULL) {
		    printf("Kyber key exchange failed. Exiting.\n");
		    close(connfd);
		    continue;
		}
		
		write(connfd,"OK",sizeOk);	
		printf("SERVER: \033[0;32mAUTHENTICATION SUCCESSFUL for %s\033[0m\n",inet_ntoa(cli_addr.sin_addr));
		fflush(stdout);

		char ping_buffer[128];
		int n = read(connfd, ping_buffer, sizeof(ping_buffer) - 1);
		ping_buffer[n] = '\0';

		if (strcmp(ping_buffer, "LATENCY_PING") == 0) {
			write(connfd, "PONG", 4);
		} else {
			printf("Error: Expected LATENCY_PING, got something else.\n");
			close(connfd);
			continue; // Go back to listening
		}
		last_refill_time = time(NULL);	//start client chat with max charges
		clientCharges=MAX_CHARGES;
		
		//chat threads		
		printf("Server key: %s\n", shared_secret_bin);
		char *motd=getMessageOfTheDay();		//send message of day to client
		printf("Word of the day is:  %s",motd);
		w=write(connfd,motd, strlen(motd));
		
		printf("\n:::Type 'STOP' to end the connection:::\n");
		sleep(2);//2sec delay
		initscr();
		start_color();
	    	cbreak();	//---BEGIN NCURSES MODE---
	    
		int height, width;
	    	getmaxyx(stdscr, height, width);
		for (int i = 0; i < LINES - 1; i++)	//push to (start chat from) the bottom
        		wprintw(stdscr, "\n");
	    	// Enable scrolling for the main window (our chat history)
	    	scrollok(stdscr, TRUE);
	    	// Clear the main screen before we start
	    	clear();	//TODO:
	    	refresh();

	    	// Create a 1-line-high window at the bottom of the screen for input
	   	input_win = newwin(1, width, height - 1, 0);
	    
	    	pthread_mutex_init(&screen_mutex, NULL);
	    	chat_is_active=1;

	    	wprintw(stdscr, "--- Chat Session Started ---\n");
	    	wrefresh(stdscr);

		// Initialize the mutex
		pthread_mutex_init(&screen_mutex, NULL);

		if (pthread_create(&send_thread, NULL, send_handler, NULL) != 0) {	//sending thread
		    perror("Failed to create send thread");
		    close(connfd);
		    continue; // Go back to listening
		}

		if (pthread_create(&recv_thread, NULL, receive_handler, NULL) != 0) {	//listening thread
		    perror("Failed to create receive thread");
		    pthread_cancel(send_thread);
		    close(connfd);
		    continue; // Go back to listening
		}

		pthread_join(send_thread, NULL);
		pthread_join(recv_thread, NULL);
		pthread_mutex_destroy(&screen_mutex);
		endwin(); 
		close(connfd);
		
	}
	return 0;
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

char *getMessageOfTheDay() {
    FILE *file = fopen("motd.txt", "r");
    if (!file) {
        perror("Could not load word of the day");
        exit(1);
    }
	int i,totLines=0,randLine;
    char *line=malloc(sizeof(char)*256);
	while (fgets(line, sizeof(line), file) != NULL)
		totLines++;
	rewind(file);
	srand(time(NULL));
    randLine=(rand()%totLines);
	for (i = 0; i < randLine; i++) {
        fgets(line, sizeof(line), file);
     }
	line[strcspn(line, "\n")] = 0;
    fclose(file);
    return line;
    free(line);
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

// This is the definitive send_handler for both client and server

void *send_handler(void *arg) {
    char plaintext_buff[MSG_BUF_SIZE];
    char prompt[] = "> ";
    
    // Buffers for the AES-GCM components
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext_buff[MSG_BUF_SIZE];
    
    // A single buffer to assemble our network packet
    unsigned char packet_buff[MSG_BUF_SIZE + IV_LEN + TAG_LEN];

    while (chat_is_active) {
        wgetstr(input_win, plaintext_buff);
        if (!chat_is_active) break;

        // Display your own message in plaintext locally
        pthread_mutex_lock(&screen_mutex);
        wprintw(stdscr, "%s%s\n", prompt, plaintext_buff);
        wnoutrefresh(stdscr);
        wclear(input_win);
        wnoutrefresh(input_win);
        doupdate();
        pthread_mutex_unlock(&screen_mutex);

        // Encrypt the message
        int ciphertext_len = aes_gcm_encrypt(
            (unsigned char*)plaintext_buff, strlen(plaintext_buff),
            shared_secret_bin,
            iv, ciphertext_buff, tag
        );
        if (ciphertext_len < 0) {
            // This is a critical error, encryption failed
            break;
        }

        // Assemble the packet: [IV][TAG][CIPHERTEXT]
        memcpy(packet_buff, iv, IV_LEN);
        memcpy(packet_buff + IV_LEN, tag, TAG_LEN);
        memcpy(packet_buff + IV_LEN + TAG_LEN, ciphertext_buff, ciphertext_len);

        size_t packet_len = IV_LEN + TAG_LEN + ciphertext_len;

        // Send the entire packet
        if (write(connfd, packet_buff, packet_len) < 0) {
            break;
        }
        
        if (strcmp(plaintext_buff, "STOP") == 0) {
            break;
        }
    }

    chat_is_active = 0;
    shutdown(connfd, SHUT_RDWR);
    pthread_exit(NULL);
}

// This is the definitive receive_handler for both client and server

void *receive_handler(void *arg) {
    unsigned char packet_buff[MSG_BUF_SIZE + IV_LEN + TAG_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext_buff[MSG_BUF_SIZE];
    unsigned char plaintext_buff[MSG_BUF_SIZE];
    int bytes_read;

    while (chat_is_active) {
    	if (!can_send_message()) {
            const char* warning_msg = "You are being rate limited. Please slow down!";
            
            unsigned char warning_iv[IV_LEN];	
            unsigned char warning_tag[TAG_LEN];
            unsigned char warning_ciphertext[MSG_BUF_SIZE];
            int warning_ct_len = aes_gcm_encrypt(
                (unsigned char*)warning_msg, strlen(warning_msg),
                shared_secret_bin,
                warning_iv, warning_ciphertext, warning_tag
            );

            if (warning_ct_len > 0) {
                unsigned char warning_packet[MSG_BUF_SIZE + IV_LEN + TAG_LEN];
                memcpy(warning_packet, warning_iv, IV_LEN);
                memcpy(warning_packet + IV_LEN, warning_tag, TAG_LEN);
                memcpy(warning_packet + IV_LEN + TAG_LEN, warning_ciphertext, warning_ct_len);
                write(connfd, warning_packet, IV_LEN + TAG_LEN + warning_ct_len);
            }
            continue; 
        }
        bytes_read = read(connfd, packet_buff, sizeof(packet_buff));
        if (bytes_read <= 0) {
            break;
        }
        // Ensure we have at least enough data for the IV and tag
        if (bytes_read < IV_LEN + TAG_LEN) {
            continue; // Invalid packet, ignore
        }
        // Disassemble the packet: [IV][TAG][CIPHERTEXT]
        memcpy(iv, packet_buff, IV_LEN);
        memcpy(tag, packet_buff + IV_LEN, TAG_LEN);
        int ciphertext_len = bytes_read - IV_LEN - TAG_LEN;
        memcpy(ciphertext_buff, packet_buff + IV_LEN + TAG_LEN, ciphertext_len);

        // Decrypt and verify the message
        int plaintext_len = aes_gcm_decrypt(
            ciphertext_buff, ciphertext_len,
            tag, shared_secret_bin, iv,
            plaintext_buff
        );
        
        pthread_mutex_lock(&screen_mutex);
	
        if (plaintext_len < 0) {
            // DECRYPTION FAILED! Tag mismatch means the message was tampered with.
            wprintw(stdscr, "[!] SECURITY ALERT: Received a corrupted or tampered message.\n");
        } else {
            // Decryption successful, display the plaintext
            init_pair(1, COLOR_CYAN, COLOR_BLACK);             
            attron(COLOR_PAIR(1));
            plaintext_buff[plaintext_len] = '\0';
            wprintw(stdscr, "Client says: %s\n", plaintext_buff);
            attroff(COLOR_PAIR(1));
        }
	if (plaintext_len > 0 && strcmp((char*)plaintext_buff, "STOP") == 0) {
            break;
        }
        wnoutrefresh(stdscr);
        wnoutrefresh(input_win);
        doupdate();
        pthread_mutex_unlock(&screen_mutex);
        
    }
    
    chat_is_active = 0;
    shutdown(connfd, SHUT_RDWR);
    pthread_exit(NULL);
}

int can_send_message() {
    time_t now = time(NULL);
    double time_elapsed = difftime(now, last_refill_time);
    
    clientCharges+=time_elapsed*CHARGE_RATE; //refill charge meter
    last_refill_time = now;

    if (clientCharges>MAX_CHARGES) {	//cap charges at max alloted
        clientCharges=MAX_CHARGES;
    }

    if (clientCharges>=1.0) {
        clientCharges-=1.0; //spend one charge
        return 1; // Success! Message is allowed.
    }
    return 0;
}

ssize_t recv_all(int connfd, void *buf, size_t len) {
    size_t total_read = 0;
    while (total_read < len) {
        ssize_t bytes_read = read(connfd, (char*)buf + total_read, len - total_read);
        if (bytes_read <= 0) {
            // Error or connection closed
            return -1;
        }
        total_read += bytes_read;
    }
    return total_read;
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
    char numstr[128];	//time wont be more than 10
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
