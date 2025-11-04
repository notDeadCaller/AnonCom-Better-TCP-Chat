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
#include <errno.h>
#include <stdatomic.h>
#include <ctype.h>
#include <oqs/oqs.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>

#define PSSWRD "theyarewatching123"
#define GOLDENKEY "DontForgetTheGoldenKey123$"
#define MAX_ALLOWED 20   //max IPs in whiteleist
#define MAX_CHARGES 10.5 //rate limiting counters
#define CHARGE_RATE 1.5

#define MAX_AUTH_FAILURES 5      //attempts before blocking
#define FAILURE_TIME_WINDOW 60   //time window (seconds) for failures
#define BLOCK_DURATION (24 * 60 * 60) //blocked IP cooldown (24 hours)
#define MAX_FAILURE_TRACK_IPS 100 // Max IPs to track recent failures for
#define MAX_BLOCKLIST_IPS 500

#define NONCE_LEN 16
#define NONCE_HEX_LEN (NONCE_LEN * 2 + 1) // Should be 33
#define SHA256_HEX_LEN (SHA256_DIGEST_LENGTH * 2 + 1) // Should be 65
#define IV_LEN 12	//AES-GCM tags
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

typedef struct {
    OQS_SIG *sig_ctx;          // Dilithium context
    uint8_t *dilithium_sk;     // Loaded secret signing key
    size_t dilithium_sk_len;
} ServerCryptoState;
typedef struct {
    char ip_addr[INET_ADDRSTRLEN];
    time_t first_failure_time;
    int failure_count;
} AuthFailureRecord;
typedef struct {	//temp blocklist IP manipulations
    char ip_addr[INET_ADDRSTRLEN];
    time_t block_expiry_time; // Timestamp when the block expires
} BlockedIPRecord;
const char* BLOCKLIST_FILENAME = "blocklist.conf";

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
void generate_nonce(char *nonce_hex_buffer);
int can_send_message();
ssize_t recv_all(int connfd, void *buf, size_t len);
void calculate_sha256(const char *input, size_t input_len, char *output_hex_hash);
long dhexchange();
char *digitsToLetters( long number);
int authenticateClient(int connfd);
void cleanup_server_keys(ServerCryptoState *state);
int load_server_keys(ServerCryptoState *state);
int load_and_clean_blocklist(BlockedIPRecord blocklist[], int max_size);
void add_ip_to_blocklist(const char* ip, BlockedIPRecord blocklist[], int* count, int max_size);
int find_ip_in_failure_log(const char* ip, AuthFailureRecord log[], int count);
int record_auth_failure(const char* ip, AuthFailureRecord failure_log[], int* count, int max_size);
void clear_auth_failures(const char* ip, AuthFailureRecord failure_log[], int count);
const char* addEmojis(const char* input);

long modexp(long base, long exp, long mod) {
    long result=1;
    base%=mod;
    while (exp>0) {
        if (exp&1) result=(result*base)%mod;
        exp>>=1;
        base=(base*base)%mod;
    }  return result;
}

int find_ip_in_blocklist(const char* ip, BlockedIPRecord blist[], int count) {
    time_t now = time(NULL);
    for (int i = 0; i < count; ++i) {
        if (strcmp(ip, blist[i].ip_addr) == 0) {
            // Found the IP, now check if the block is still active
            if (difftime(blist[i].block_expiry_time, now) > 0) {
                return i; // IP found and block is active
            } else {
                // IP found, but block has expired (should ideally be cleaned already)
                return -1; // Treat as not blocked
            }
        }
    }
    return -1; // IP not found in the blocklist
}

uint8_t* authenticated_kyber_exchange_server(int connfd, ServerCryptoState *crypto_state) {
    OQS_STATUS status;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) return NULL;

    uint8_t *kyber_pk = malloc(kem->length_public_key);
    uint8_t *kyber_sk = malloc(kem->length_secret_key);
    uint8_t *signature = malloc(crypto_state->sig_ctx->length_signature);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_bin = malloc(kem->length_shared_secret);

    if (!kyber_pk || !kyber_sk || !signature || !ciphertext || !shared_secret_bin) {
        fprintf(stderr, "ERROR: Memory allocation failed in server exchange\n");
        goto cleanup; // Use goto for centralized cleanup on error
    }

    // 1. Generate ephemeral Kyber keypair
    status = OQS_KEM_keypair(kem, kyber_pk, kyber_sk);
    if (status != OQS_SUCCESS) { fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n"); goto cleanup; }

    // 2. Sign the ephemeral Kyber public key
    size_t signature_len;
    status = OQS_SIG_sign(crypto_state->sig_ctx, signature, &signature_len,
                          kyber_pk, kem->length_public_key, crypto_state->dilithium_sk);
    if (status != OQS_SUCCESS) { fprintf(stderr, "ERROR: OQS_SIG_sign failed\n"); goto cleanup; }
    if (signature_len != crypto_state->sig_ctx->length_signature) {
        fprintf(stderr, "ERROR: Signature length mismatch\n"); goto cleanup;
    }

    // 3. Send Kyber PK + Signature
    if (write(connfd, kyber_pk, kem->length_public_key) < 0) { perror("write kyber_pk"); goto cleanup; }
    if (write(connfd, signature, signature_len) < 0) { perror("write signature"); goto cleanup; }

    // 4. Receive Kyber Ciphertext
    if (recv_all(connfd, ciphertext, kem->length_ciphertext) < 0) {
        perror("Failed to receive ciphertext");
        goto cleanup;
    }

    // 5. Decapsulate
    status = OQS_KEM_decaps(kem, shared_secret_bin, ciphertext, kyber_sk);
    if (status != OQS_SUCCESS) { fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n"); goto cleanup; }

    // Success path: Clean up everything except the shared secret
    free(kyber_pk);
    free(kyber_sk);
    free(signature);
    free(ciphertext);
    OQS_KEM_free(kem);
    return shared_secret_bin;

cleanup:
    // Error path: Clean up everything including the shared secret buffer
    free(kyber_pk);
    free(kyber_sk);
    free(signature);
    free(ciphertext);
    free(shared_secret_bin); // Free this too on error
    OQS_KEM_free(kem);
    return NULL;
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
	const int sizeOk=3;
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	printf("<ANON COMM: SERVER CLI>\n");
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
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
	ServerCryptoState server_keys;
	AuthFailureRecord failure_log[MAX_FAILURE_TRACK_IPS];
        int failure_log_count = 0;
        BlockedIPRecord blocklist[MAX_BLOCKLIST_IPS];
        int blocklist_count = 0;
    	if (!load_server_keys(&server_keys)) {
    		printf("SERVER ERROR failed to load keys");
        	return 1; // Failed to load keys
    	}
    	blocklist_count = load_and_clean_blocklist(blocklist, MAX_BLOCKLIST_IPS);

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

		//BLOCKLIST VERIFICATIONS
		int blocked_idx = find_ip_in_blocklist(client_ip, blocklist, blocklist_count);
        	if (blocked_idx != -1) {
            	 if (difftime(blocklist[blocked_idx].block_expiry_time, time(NULL)) > 0) {
                 	printf("\a\033[0;31mConnection from %s REJECTED (IP is blocked)\033[0m\n", client_ip);
                 	close(connfd);
                 	continue;
           	  } else
                 	printf("Info: Found expired blocklist entry for %s during check.\n", client_ip);
       	 	}


        	//size_t key_len = 32; // Kyber-768 secret length
		int auth_result = authenticateClient(connfd);
		if (auth_result==0) {	//if either auth fail, then stop
	 	    if (record_auth_failure(client_ip, failure_log, &failure_log_count, MAX_FAILURE_TRACK_IPS)) {
                	// Threshold met, block the IP
                	add_ip_to_blocklist(client_ip, blocklist, &blocklist_count, MAX_BLOCKLIST_IPS);
            	    }
		    printf("\a\033[0;31mSERVER: Connection from %s REJECTED\033[0m\n",client_ip);
		    close(connfd);
		    continue;
		}
		if (!isAllowed(client_ip) && goldenKeyFlag == 0) {
            // Client is NOT on the allowlist, AND they did NOT use the golden key.
            printf("\a\033[0;31mConnection from %s DENIED (not in allowlist)\033[0m\n", client_ip);
            const char* allow_msg = "ERROR: Connection rejected. Your IP is not on the allowlist.\n";
            write(connfd, allow_msg, strlen(allow_msg));
            close(connfd);
			continue;
        }
        shared_secret_bin = authenticated_kyber_exchange_server(connfd, &server_keys);
        if (goldenKeyFlag) {
            printf("Firewall: Golden Key bypass active for %s.\n", client_ip);
        } else {
            printf("Firewall: Client IP %s is allowed.\n", client_ip);
        }
		if (shared_secret_bin == NULL) {
		    printf("Authenticated key exchange failed for %s.\n", client_ip);
		    close(connfd);
		    continue;
		}
        	/*else if (!isAllowed(client_ip)) { //if not allowlisted...
	        	if(goldenKeyFlag) printf("***Firewall BYPASSED***\n"); //but used Goldenkey access
	        	else {	//if not in alowlist + normal password used, then stop
			printf("\a\033[0;31mConnection from %s DENIED (not in allowlist)\033[0m\n", client_ip);
			close(connfd);
			continue; }
		} else
		 	clear_auth_failures(client_ip, failure_log, failure_log_count);*/

		//const long key=dhexchange();

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
			free(shared_secret_bin);
			close(connfd);
			continue; // Go back to listening
		}
		last_refill_time = time(NULL);	//start client chat with max charges
		clientCharges=MAX_CHARGES;
		fflush(stdout);

		//chat threads
		printf("Server key: %s\n", shared_secret_bin);
		char *motd=getMessageOfTheDay();		//send message of day to client
		printf("Word of the day is:  %s",motd);
		w=write(connfd,motd, strlen(motd));

		printf("\n:::Type \033[0;31m'STOP'\033[0m to end the connection:::\n");
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
		    free(shared_secret_bin);
		    close(connfd);
		    continue; // Go back to listening
		}

		if (pthread_create(&recv_thread, NULL, receive_handler, NULL) != 0) {	//listening thread
		    perror("Failed to create receive thread");
		    pthread_cancel(send_thread);
		    free(shared_secret_bin);
		    close(connfd);
		    continue; // Go back to listening
		}

		pthread_join(send_thread, NULL);
		pthread_join(recv_thread, NULL);
		pthread_mutex_destroy(&screen_mutex);
		endwin();
		free(shared_secret_bin);
		close(connfd);

	}
	cleanup_server_keys(&server_keys);
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

void *send_handler(void *arg) {
    char plaintext_buff[MSG_BUF_SIZE];
    char prompt[] = "> ";

    // Buffers for the AES-GCM components
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext_buff[MSG_BUF_SIZE];

    // A single buffer to assemble our network packet
    unsigned char packet_buff[MSG_BUF_SIZE + IV_LEN + TAG_LEN];
    //wtimeout(input_win, 100);

    while (chat_is_active) {
        wgetstr(input_win, plaintext_buff);
        if (!chat_is_active) break;
	const char* final_message = addEmojis(plaintext_buff);
        // Display your own message in plaintext locally
        pthread_mutex_lock(&screen_mutex);
        wprintw(stdscr, "%s%s\n", prompt, final_message);
        wnoutrefresh(stdscr);
        wclear(input_win);
        wnoutrefresh(input_win);
        doupdate();
        pthread_mutex_unlock(&screen_mutex);

        // Encrypt the message
        int ciphertext_len = aes_gcm_encrypt(
            (unsigned char*)final_message, strlen(final_message),
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
	    chat_is_active = 0;
            break;
        }
    }

    chat_is_active = 0;
    shutdown(connfd, SHUT_RDWR);
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
	bytes_read=read(connfd, packet_buff, sizeof(packet_buff));
	if (bytes_read <= 0) {
            break;
        }
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
                write(connfd, warning_packet, (IV_LEN + TAG_LEN + warning_ct_len));
            }
            continue;
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
            wprintw(stdscr, "***SECURITY ALERT: Received a corrupted or tampered message***\n");
        } else {
            // Decryption successful, display the plaintext
            init_pair(1, COLOR_CYAN, COLOR_BLACK);
            attron(COLOR_PAIR(1));
            plaintext_buff[plaintext_len] = '\0';
            wprintw(stdscr, "Client says: %s\n", plaintext_buff);
            attroff(COLOR_PAIR(1));
            if (plaintext_len > 0 && strcmp((char*)plaintext_buff, "STOP") == 0) {
            	chat_is_active=0;
            	break;
            }
        }

        wnoutrefresh(stdscr);
        wnoutrefresh(input_win);
        doupdate();
        pthread_mutex_unlock(&screen_mutex);
        if(!chat_is_active) break;
    }

    chat_is_active = 0;
    shutdown(connfd, SHUT_RDWR);
    pthread_exit(NULL);
}

void generate_nonce(char *nonce_hex_buffer) {
    unsigned char nonce_bin[NONCE_LEN];
    if (1 != RAND_bytes(nonce_bin, NONCE_LEN)) {
        perror("RAND_bytes failed");
        exit(1);
    }

    for (int i = 0; i < NONCE_LEN; i++) {	//conv to hex
        sprintf(nonce_hex_buffer + (i * 2), "%02x", nonce_bin[i]);
    }
    nonce_hex_buffer[NONCE_HEX_LEN - 1] = '\0';
}

void calculate_sha256(const char *input, size_t input_len, char *output_hex_hash) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash_bin[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;

    // 1. Get the SHA256 message digest type
    md = EVP_sha256();
    if (md == NULL) {
        fprintf(stderr, "EVP_sha256() failed\n");
        exit(1);
    }
    // 2. Create and initialize the context
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        exit(1);
    }
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex() failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    // 3. Provide the data to be hashed
    if (1 != EVP_DigestUpdate(mdctx, input, input_len)) {
        fprintf(stderr, "EVP_DigestUpdate() failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    // 4. Finalize the hash
    if (1 != EVP_DigestFinal_ex(mdctx, hash_bin, &hash_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex() failed\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    // 5. Clean up the context
    EVP_MD_CTX_free(mdctx);

    // Sanity check: Ensure the output length is correct for SHA256
    if (hash_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "SHA256 output length mismatch!\n");
        exit(1);
    }
    // 6. Convert the binary hash to a hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex_hash + (i * 2), "%02x", hash_bin[i]);
    }
    // HASH_LEN should be 65 (SHA256_DIGEST_LENGTH * 2 + 1)
    output_hex_hash[SHA256_HEX_LEN * 2] = '\0';
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

int authenticateClient(int connfd) {
    char client_nonce[NONCE_HEX_LEN];
    char server_nonce[NONCE_HEX_LEN];
    char client_proof_from_client[SHA256_HEX_LEN];
    char local_client_proof_normal[SHA256_HEX_LEN]; // Proof using normal password
    char local_client_proof_golden[SHA256_HEX_LEN]; // Proof using golden key
    char local_server_proof[SHA256_HEX_LEN];
    char proof_input_buffer[512];
    ssize_t bytes_read;
    const char* correct_password = NULL; // To store which password worked

    // Reset golden key flag for this session
    goldenKeyFlag = 0;

    // 1. Wait for the client's challenge using recv_all
    bytes_read = recv_all(connfd, client_nonce, NONCE_HEX_LEN - 1);
    if (bytes_read <= 0) {
        printf("Failed to receive client nonce.\n");
        return 0;
    }
    client_nonce[bytes_read] = '\0';

    // 2. Generate and send the server's challenge (server_nonce)
    generate_nonce(server_nonce);
    if (write(connfd, server_nonce, strlen(server_nonce)) <= 0) {
        printf("Failed to write server nonce.\n");
        return 0;
    }

    // 3. Receive the client's proof using recv_all
    bytes_read = recv_all(connfd, client_proof_from_client, SHA256_HEX_LEN - 1);
    if (bytes_read <= 0) {
        printf("Failed to receive client proof.\n");
        return 0;
    }
    client_proof_from_client[bytes_read] = '\0';

    // 4. Verify the client's proof against the NORMAL password
    int len_to_hash = sprintf(proof_input_buffer, "%s%s%s", PSSWRD, client_nonce, server_nonce);
    calculate_sha256(proof_input_buffer, len_to_hash, local_client_proof_normal);

    if (strcmp(local_client_proof_normal, client_proof_from_client) == 0) {
        // Normal password matched!
        correct_password = PSSWRD;
        printf("**Client used NORMAL password**\n");
    } else {
        // Normal password failed, try the GOLDEN KEY
        len_to_hash=sprintf(proof_input_buffer, "%s%s%s", GOLDENKEY, client_nonce, server_nonce);
        calculate_sha256(proof_input_buffer, len_to_hash, local_client_proof_golden);

        if (strcmp(local_client_proof_golden, client_proof_from_client) == 0) {
            correct_password = GOLDENKEY;
            goldenKeyFlag = 1; // Set the flag
            printf("*** Golden Key ACTIVATED ***\n");
        } else {
            // NEITHER matched
            printf("SERVER Password mismatch\n");
            write(connfd, "FAIL", 4);
            return 0;
        }
    }

    // 5. Client is valid (using either password). Send our proof based on the correct password.
    len_to_hash=sprintf(proof_input_buffer, "%s%s%s", correct_password, server_nonce, client_nonce);
    calculate_sha256(proof_input_buffer, len_to_hash, local_server_proof);

    if (write(connfd, local_server_proof, strlen(local_server_proof)) <= 0) {
        printf("Failed to write server proof.\n");
        return 0;
    }

    return 1;
}

void cleanup_server_keys(ServerCryptoState *state) {
    if (state->sig_ctx) OQS_SIG_free(state->sig_ctx);
    if (state->dilithium_sk) free(state->dilithium_sk);
    state->sig_ctx = NULL;
    state->dilithium_sk = NULL;
}

int load_server_keys(ServerCryptoState *state) {
    state->sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!state->sig_ctx) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
        return 0;
    }
    state->dilithium_sk_len = state->sig_ctx->length_secret_key;
    state->dilithium_sk = malloc(state->dilithium_sk_len);
    if (!state->dilithium_sk) {
        fprintf(stderr, "ERROR: malloc failed for dilithium sk\n");
        OQS_SIG_free(state->sig_ctx);
        return 0;
    }

    FILE *f_sk = fopen("server_dilithium.key", "rb");
    if (!f_sk) {
        perror("FATAL: Could not load server_dilithium.key. Run gen_keys first.");
        free(state->dilithium_sk);
        OQS_SIG_free(state->sig_ctx);
        return 0;
    }
    if (fread(state->dilithium_sk, 1, state->dilithium_sk_len, f_sk) != state->dilithium_sk_len) {
        fprintf(stderr, "ERROR: Failed to read complete dilithium secret key.\n");
        fclose(f_sk);
        free(state->dilithium_sk);
        OQS_SIG_free(state->sig_ctx);
        return 0;
    }
    fclose(f_sk);
    printf("Loaded long-term signing key from server_dilithium.key\n");
    return 1;
}

int load_and_clean_blocklist(BlockedIPRecord blocklist[], int max_size) {
    FILE *f_read = fopen(BLOCKLIST_FILENAME, "r");
    if (!f_read) {
        if (errno == ENOENT) { // File not found is okay on first run
            return 0;
        }
        perror("Error opening blocklist for reading");
        return 0; // Return 0, proceed without blocklist
    }

    BlockedIPRecord temp_list[max_size]; // Temporary storage
    int temp_count = 0;
    char line[INET_ADDRSTRLEN + 20]; // IP + comma + timestamp + newline
    time_t now = time(NULL);

    while (fgets(line, sizeof(line), f_read) && temp_count < max_size) {
        char *ip_part = strtok(line, ",");
        char *time_part = strtok(NULL, "\n");

        if (ip_part && time_part) {
            time_t expiry_time = (time_t)atol(time_part);
            if (difftime(expiry_time, now) > 0) { // Check if block is still active
                strncpy(temp_list[temp_count].ip_addr, ip_part, INET_ADDRSTRLEN - 1);
                temp_list[temp_count].ip_addr[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null termination
                temp_list[temp_count].block_expiry_time = expiry_time;
                temp_count++;
            } else {
                 printf("Blocklist: Expired entry for %s removed.\n", ip_part);
            }
        }
    }
    fclose(f_read);

    // Rewrite the blocklist file with only active entries
    FILE *f_write = fopen(BLOCKLIST_FILENAME, "w");
    if (!f_write) {
        perror("Error opening blocklist for writing cleaned list");
        // Continue with the in-memory list, but persistence might fail
    } else {
        for (int i = 0; i < temp_count; ++i) {
            fprintf(f_write, "%s,%ld\n", temp_list[i].ip_addr, temp_list[i].block_expiry_time);
        }
        fclose(f_write);
    }

    // Copy active entries to the main blocklist array
    memcpy(blocklist, temp_list, temp_count * sizeof(BlockedIPRecord));
    printf("Loaded %d active blocks from %s\n", temp_count, BLOCKLIST_FILENAME);
    return temp_count;
}

//function to add an IP to blocklist file and in-memory list
void add_ip_to_blocklist(const char* ip, BlockedIPRecord blocklist[], int* count, int max_size) {
    // Check if already in memory (shouldn't happen often with load check)
    for(int i = 0; i < *count; ++i) {
        if (strcmp(blocklist[i].ip_addr, ip) == 0) {
            return; // Already blocked
        }
    }
    if (*count >= max_size) {
        printf("Warning: In-memory blocklist full. Cannot block %s\n", ip);
        return; // Cannot add more
    }

    time_t now = time(NULL);
    time_t expiry_time = now + BLOCK_DURATION;

    // Add to in-memory list
    strncpy(blocklist[*count].ip_addr, ip, INET_ADDRSTRLEN - 1);
    blocklist[*count].ip_addr[INET_ADDRSTRLEN - 1] = '\0';
    blocklist[*count].block_expiry_time = expiry_time;
    (*count)++;

    // Append to persistent file
    FILE *f_append = fopen(BLOCKLIST_FILENAME, "a");
    if (!f_append) {
        perror("Error opening blocklist for appending");
        // Block is active in memory for this session, but won't persist if server restarts now
    } else {
        fprintf(f_append, "%s,%ld\n", ip, expiry_time);
        fclose(f_append);
    }
    printf("\033[0;31mBlocked IP %s until %ld (%.0f seconds)\033[0m\n", ip, expiry_time, difftime(expiry_time, now));
}

int find_ip_in_failure_log(const char* ip, AuthFailureRecord log[], int count) {
    for (int i = 0; i < count; ++i) {
        if (strcmp(ip, log[i].ip_addr) == 0) {
            return i;
        }
    }
    return -1;
}
int record_auth_failure(const char* ip, AuthFailureRecord failure_log[], int* count, int max_size) {
    time_t now = time(NULL);
    int index = find_ip_in_failure_log(ip, failure_log, *count);

    if (index != -1) {
        // IP found, check time window
        if (difftime(now, failure_log[index].first_failure_time) < FAILURE_TIME_WINDOW) {
            failure_log[index].failure_count++; // Increment count within window
        } else {
            // Outside window, reset the count and window start time
            failure_log[index].failure_count = 1;
            failure_log[index].first_failure_time = now;
        }
    } else {
        // IP not found, add if space allows
        if (*count < max_size) {
            strncpy(failure_log[*count].ip_addr, ip, INET_ADDRSTRLEN - 1);
            failure_log[*count].ip_addr[INET_ADDRSTRLEN - 1] = '\0';
            failure_log[*count].first_failure_time = now;
            failure_log[*count].failure_count = 1;
            (*count)++;
            index = *count - 1; // Index of the newly added entry
        } else {
            printf("Warning: Failure log full. Cannot track failures for %s\n", ip);
            return 0; // Cannot block if we can't track
        }
    }

    // Check if block threshold is met
    if (failure_log[index].failure_count >= MAX_AUTH_FAILURES) {
        // Reset count immediately to prevent re-blocking on next failure
        failure_log[index].failure_count = 0;
        return 1; // Signal that blocking is needed
    }

    return 0; // Threshold not met
}

// --- Function to clear failure count on success ---
void clear_auth_failures(const char* ip, AuthFailureRecord failure_log[], int count) {
     int index = find_ip_in_failure_log(ip, failure_log, count);
     if (index != -1) {
         failure_log[index].failure_count = 0;
     }
}

const char* addEmojis(const char* input) {
    if (strcmp(input, "/shrug") == 0) {
        return "¯\\_(ツ)_/¯";
    }
    if (strcmp(input, "/happy") == 0) {
        return "(・3・)";
    }
    if (strcmp(input, "/lol") == 0 || strcmp(input, "/laugh") == 0 || strcmp(input, "/lmao") == 0) {
        return "L(° O °L)";
    }
    if (strcmp(input, "/tableflip") == 0) {
        return "(╯°□°）╯︵ ┻━┻";
    }
    if (strcmp(input, "/sad") == 0) {
        return "(´סּ︵סּ`)";
    }
    if (strcmp(input, "/unflip") == 0) {
        return "┬─┬ ノ( ゜-゜ノ)";
    }
    return input;
}
