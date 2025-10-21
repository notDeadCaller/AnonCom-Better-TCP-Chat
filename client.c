
//Post Quantum TCP Chat Client Pragram

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
#include<signal.h>
#include<oqs/oqs.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#define IV_LEN 12
#define TAG_LEN 16
#define MSG_BUF_SIZE 256

uint8_t *shared_secret_bin = NULL;
size_t shared_secret_len = 0;

struct sockaddr_in serv_addr;

int skfd, r, w;
unsigned short serv_port; 
char serv_ip[20];// = "127.0.0.1"; //152.67.7.144: cloudboot
WINDOW *input_win;		//ncurses window thingy
pthread_mutex_t screen_mutex;		//ncurses Window thread
pthread_t send_thread, recv_thread;	//chat thread
volatile sig_atomic_t chat_is_active = 1;

char rbuff[128];	//stores strings received frm server
char sbuff[128];	//stores wtv client inputs

void *send_handler(void *arg);
void *receive_handler(void *arg);
char *digitsToLetters( long number);
ssize_t recv_all(int sockfd, void *buf, size_t len);
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

uint8_t* kyber_key_exchange_client(int skfd) {
    OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return NULL;

    uint8_t *public_key=malloc(kem->length_public_key);	//helper to confirm receipt of all info
    if (recv_all(skfd, public_key, kem->length_public_key) < 0) {
        perror("Failed to receive public key");
        return NULL;
    }

    //encapsulate to reveal secret shared key
    uint8_t *ciphertext=malloc(kem->length_ciphertext);
    uint8_t *shared_secret_bin1=malloc(kem->length_shared_secret);
    OQS_KEM_encaps(kem, ciphertext, shared_secret_bin1, public_key);

    //send the ciphertext back to the server
    write(skfd, ciphertext, kem->length_ciphertext);

    free(public_key);
    free(ciphertext);
    //free(shared_secret_bin);
    OQS_KEM_free(kem);

    return shared_secret_bin1; //return the Base64 encoded key
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
	
	if((w=write(skfd, sbuff, 28))<0) {		//send password/goldkey
		printf("CLIENT ERROR: Cannot send password to server\n");
		close(skfd);
		exit(1);
	}
	//const long key=dhexchange();
	shared_secret_bin=kyber_key_exchange_client(skfd);
	if (shared_secret_bin==NULL) {
	    printf("Kyber key exchange failed. Exiting.\n");
	    close(skfd);
	    exit(1);
	}
	
	if((r=read(skfd,rbuff,128))<0) {
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

	//char *charKey=digitsToLetters(shared_key_string);
	printf("Client key: %s\n", shared_secret_bin);	//key for the session
	r=read(skfd,rbuff,128);		//read message of day frm server
	rbuff[r]='\0';
	printf("Message of the day is:  %s",rbuff);
	chat_is_active=1;
	
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
	free(shared_secret_bin);
	exit(1);
}

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
        if (write(skfd, packet_buff, packet_len) < 0) {
            break;
        }
        
        if (strcmp(plaintext_buff, "STOP") == 0) {
            break;
        }
    }

    chat_is_active = 0;
    shutdown(skfd, SHUT_RDWR);
    pthread_exit(NULL);
}

void *receive_handler(void *arg) {
    unsigned char packet_buff[MSG_BUF_SIZE + IV_LEN + TAG_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext_buff[MSG_BUF_SIZE];
    unsigned char plaintext_buff[MSG_BUF_SIZE];
    int bytes_read;

    while (chat_is_active) {
        bytes_read = read(skfd, packet_buff, sizeof(packet_buff));
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
            wprintw(stdscr, "Server says: %s\n", plaintext_buff);
            attroff(COLOR_PAIR(1));
        }

        wnoutrefresh(stdscr);
        wnoutrefresh(input_win);
        doupdate();
        pthread_mutex_unlock(&screen_mutex);
        
        if (plaintext_len > 0 && strcmp((char*)plaintext_buff, "STOP") == 0) {
            break;
        }
    }
    
    chat_is_active = 0;
    shutdown(skfd, SHUT_RDWR);
    pthread_exit(NULL);
}

ssize_t recv_all(int sockfd, void *buf, size_t len) {
    size_t total_read = 0;
    while (total_read < len) {
        ssize_t bytes_read = read(sockfd, (char*)buf + total_read, len - total_read);
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
