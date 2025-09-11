**# TCP-Chat**
goofy ahh private (hoepfully) TCP Chat

**How to Use Client?**
Download the client.c file
Compile it using 'gcc client.c' on any linux terminal (tested on WSL/Termux/VMWare using Ubuntu/Kali)
Execute using './a.out'
Enter the public host IP '152.67.7.144'
Enter the port '25020'
Enter the password (if in allowlist) else the golden passkey
Beep Boop - You're in!...as long as my server.c is running ;)

-------------------------
Log 1 ("_the first 04:04_")
03.Sep.2025

ADDED 'client.c' and 'server.c'
  Features as of this commit:
      -Standard 1on1 TCP based CLI chat service 
      -Password authentication
      -Private to public IP tunelling via Cloudboot.in

-------------------------
Log 2 ("_they are watching_")
06.Sep.2025

UPDATED 'client.c' and 'server.c'
ADDED 'firewall.conf'
  Features as of this commit:
      -Added an in-code, toy firewall via IP allowlisting
      -Accomodate spaces in between chat message sentences
      -Fixed a potential security risk in variable handling

-------------------------
Log 3 ("_You didn't say the magic word!_")
11.Sep.2025

UPDATED 'client.c' and 'server.c'
  Features as of this commit:
      -Added a golden passkey, when entered, skips the firewall checking
      -Added colors to console lines at important checkpoints
      -Added sound pings as notifcation for message receipt
      -Improved console text formatting
