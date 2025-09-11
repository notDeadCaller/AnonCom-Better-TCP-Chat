# TCP-Chat
goofy ahh private (hoepfully) TCP Chat

-------------------------
Log 1 ("the first 04:04")
03.Sep.2025

ADDED 'client.c' and 'server.c'
  Features as of this commit:
      -Standard 1on1 TCP based CLI chat service 
      -Password authentication
      -Private to public IP tunelling via Cloudboot.in

-------------------------
Log 2 ("they are watching")
06.Sep.2025

UPDATED 'client.c' and 'server.c'
ADDED 'firewall.conf'
  Features as of this commit:
      -Added an in-code, toy firewall via IP allowlisting
      -Accomodate spaces in between chat message sentences
      -Fixed a potential security risk in variable handling

-------------------------
Log 3 ("You didn't say the magic word!")
11.Sep.2025

UPDATED 'client.c' and 'server.c'
  Features as of this commit:
      -Added a golden passkey, when entered, skips the firewall checking
      -Added colors to console lines at important checkpoints
      -Added sound pings as notifcation for message receipt
      -Improved console text formatting
