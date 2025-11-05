# AnonCom: Better-TCP-Chat 
goofy ahh private (hoepfully) TCP Chat

Client <br>
  ↓  <br>
Firewall / Network Filters <br>
  ↓  <br>
Post-Quantum Handshake (Kyber KEM + optional hybrid) <br>
  ↓
Session Manager (key rotation + nonces) <br>
  ↓
Encryption Layer (AES/GCM or similar) <br>
  ↓
Transport Queue <br>
  ↓
Server <br>

**How to Use Client?** <br>
Download the client.c, Makefile, setup.sh and runClient.sh files <br>
Get dependencies [liboqs](https://github.com/open-quantum-safe/liboqs) using `./setup.sh` on any linux terminal (tested on WSL/Termux/VMWare using Ubuntu/Kali) <br>
Compile using `make` <br?
Execute using `./runClient.sh` for 1st time or simply `./client` for subsequent executions <br>
Enter the public host IP `152.67.7.144` <br>
Enter the port `25021` <br>
Enter the password (if in allowlist) else the golden passkey <br>
Beep Boop - You're in!...as long as my server.c is running ;) <br>

-------------------------
Log 1 ("_the first 04:04_") <br>
03.Sep.2025

ADDED 'client.c' and 'server.c' <br>
  Features as of this commit:<br>
- [x] Standard 1on1 TCP based CLI chat service
- [x] Password authentication 
- [x] Private to public IP tunelling via Cloudboot.in

-------------------------
Log 2 ("_they are watching_") <br>
06.Sep.2025

UPDATED 'client.c' and 'server.c' <br>
ADDED 'firewall.conf' <br>
  Features as of this commit:
- [x] Added an in-code, toy firewall via IP allowlisting
- [x] Accomodate spaces in between chat message sentences
- [x] Fixed a potential security risk in variable handling

-------------------------
Log 3 ("_Uh uh uh! You didn't say the magic word!_") <br>
11.Sep.2025

UPDATED 'client.c' and 'server.c'<br>
  Features as of this commit:<br>
- [x] Added a golden passkey, when entered, skips the firewall checking<br>
- [x] Added colors to console lines at important checkpoints<br>
- [x] Added sound pings as notifcation for message receipt<br>
- [x] Improved console text formatting<br>

-------------------------
Log 4 ("_for the unkown listeners of the night_") <br>
27.Sep.2025

UPDATED 'client.c' and 'server.c'<br>
  Features as of this commit:<br>
- [x] Added two-way encryption in chat messages using the Vigenere Cipher<br>
- [x] Added Diffie-Hellman Exchange protocol to generate & exchange server & client side keys<br>
- [x] Added the rotating dash waiting animation using threads
- [x] Optimized functions and scope of variables as necessary

-------------------------
Log 5 ("_Keep em coming_") <br>
03.Oct.2025

UPDATED 'client.c' and 'server.c'<br>
  Features as of this commit:<br>
- [x] Added asynchronous texting for using separate threads for sending() & receiving()<br>
- [x] Added clientside RTT latency checker keys<br>
- [x] Optimized client code by removing stale functions

-------------------------
Log 6 ("_Repair, Reflect and Re-emerge_") <br>
08.Oct.2025

UPDATED 'client.c' and 'server.c'<br>
ADDED 'motd.txt' <br>
  Features as of this commit:<br>
- [x] Remodelled chat threads and fixed a major practical issue* of asynchronous chat using the ncurses library<br>
- [x] Significant terminal UI overhaul<br>
- [x] Added rate limiting for clients via Token Bucket principle<br>
- [x] Added a word of the day for each chat session<br>

-------------------------
Log 7 ("_Wanted dead ~~or~~ and alive_") <br>
21.Oct.2025

UPDATED 'client.c' and 'server.c'<br>
ADDED 'Makefile' <br>
ADDED 'setup.sh' <br>
ADDED './runServer.c' and './runClient' <br>
  Features as of this commit:<br>
- [x] Added postquantum cryptographic security via the CRYSTALS-Kyber 768 algorithm for the shared session key, replacing Diffie Hellman Key Exchange<br>
- [x] Added the AES-GCM 256 standard cipher for encrypt/decryption of chat messages, along with its innate HMAC principle, replacing Vigenere Cipher<br>
- [x] Optimized the workflow for first time users via Makefile and setup.sh files<br>
- [x] Code revision to remove obselete functions<br>
- [x] Updated the token refill rate for rate limiting<br>


--------------------------

# Dependencies
This project requires the **Open Quantum Safe (OQS)** library (`liboqs`) for its post-quantum cryptography. The `setup.sh` script will automatically clone and build it.

- **`liboqs`:** [https://github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- `liboqs` is licensed under the MIT license.
