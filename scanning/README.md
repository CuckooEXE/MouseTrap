# Scanning

This directory contains some resources for scanning for RemoteMouse servers

## Nmap

An [nmap-service-probes](https://nmap.org/book/vscan-fileformat.html#vscan-fileformat-example) file dictates service/banner scanning. 

Example usage:
```bash
$ sudo nmap -sV -p1978 192.168.86.195 --versiondb scanning/nmap-remotemouse-probe                                                                   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-10 09:10 EST
Nmap scan report for desktop-biicve8.lan (192.168.86.195)
Host is up (0.000082s latency).

PORT     STATE SERVICE     VERSION
1978/tcp open  remotemouse RemoteMouse
MAC Address: A4:C3:F0:65:6E:6D (Intel Corporate)
Service Info: OS: Windows

Read from /usr/bin/../share/nmap: nmap-mac-prefixes nmap-payloads nmap-services.
Read from scanning: nmap-remotemouse-probe.
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```

And an example with a password-protected RemoteMouse sessions:
```bash
$ sudo nmap -sV -p1978 192.168.86.195 --versiondb scanning/nmap-remotemouse-probe
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-10 09:12 EST
Nmap scan report for desktop-biicve8.lan (192.168.86.195)
Host is up (0.00020s latency).

PORT     STATE SERVICE     VERSION
1978/tcp open  remotemouse RemoteMouse (Password Protected)
MAC Address: A4:C3:F0:65:6E:6D (Intel Corporate)
Service Info: OS: Windows

Read from /usr/bin/../share/nmap: nmap-mac-prefixes nmap-payloads nmap-services.
Read from scanning: nmap-remotemouse-probe.
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
```