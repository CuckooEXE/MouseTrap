# MouseTrap

MouseTrap is a suite of vulernabilities/exploit that targets the RemoteMouse application and server. As of release date 05/06/2021, the vulnerabilities have not been patched.

[![MouseTrap](https://img.youtube.com/vi/1ceS8T2Xack/0.jpg)](https://www.youtube.com/watch?v=1ceS8T2Xack "MouseTrap")


## Vulnerabilities

It's clear that this application is very vulnerable and puts users at risk with bad authentication mechanisms, lack of encryption, and poor default configuration. With 10,000,000+ downloads on the Android App Store _alone_, there are a lot of oblivious users who could be completely owned without ever realizing. Here are the vulnerabilities/weaknesses documented:

- **CVE-2021-27569**: An issue was discovered in Emote Remote Mouse through 3.015. Attackers can maximize or minimize the window of a running process by sending the process name in a crafted packet. This information is sent in cleartext and is not protected by any authentication logic.
- **CVE-2021-27570**: An issue was discovered in Emote Remote Mouse through 3.015. Attackers can close any running process by sending the process name in a specially crafted packet. This information is sent in cleartext and is not protected by any authentication logic.
- **CVE-2021-27571**: An issue was discovered in Emote Remote Mouse through 3.015. Attackers can retrieve recently used and running applications, their icons, and their file paths. This information is sent in cleartext and is not protected by any authentication logic.
- **CVE-2021-27572**: An issue was discovered in Emote Remote Mouse through 3.015. Authentication Bypass can occur via Packet Replay. Remote unauthenticated users can execute arbitrary code via crafted UDP packets even when passwords are set.
- **CVE-2021-27573**: An issue was discovered in Emote Remote Mouse through 3.015. Remote unauthenticated users can execute arbitrary code via crafted UDP packets with no prior authorization or authentication.
- **CVE-2021-27574**: An issue was discovered in Emote Remote Mouse through 3.015. It uses cleartext HTTP to check, and request, updates. Thus, attackers can machine-in-the-middle a victim to download a malicious binary in place of the real update, with no SSL errors or warnings.

## Writeup

Please refer to my [blog](https://axelp.io/MouseTrap/) for the full writeup.

## Special Thanks

Special thanks to [Matt Matteis](https://www.linkedin.com/in/matthew-matteis-616a33bb/) for reviewing this report and guiding me through the disclosure process.

Another special thanks to [Kieran London](https://github.com/kieranlondon), without him I would have never figured out a bug in my mapping of the targets in the Analysis section.
