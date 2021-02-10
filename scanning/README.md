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

## Masscan -> Nmap

Before building a protocol analyzer with masscan, let's just scan the internet for port 1978 (convenient that the software doesn't allow you to change the port, so unless you have a Reverse-Proxy, it's static), and pipe those results to Nmap. I'm going to go ahead and build masscan from source, so I can quickly just implement my patch if I ever get around to building a protocol analyzer for the server.  This is all done on a bare-metal cloud-hosted VPS.

```bash
# Commands from https://github.com/robertdavidgraham/masscan#building
sudo apt-get --assume-yes install git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make -j
make test
```

I'm also going to firewall the port that masscan uses so I can grab banners as well: `iptables -A INPUT -p tcp --dport 61000 -j DROP`


Then, in order to speed up my scan, I'll create a file that has IP addresses that I know won't return results, this is actually from the first part of the repo's exclude configuration:

```
# http://tools.ietf.org/html/rfc5735
# "This" network
0.0.0.0/8
# Private networks
10.0.0.0/8
# Carrier-grade NAT - RFC 6598
100.64.0.0/10
# Host loopback
127.0.0.0/8
# Link local
169.254.0.0/16
# Private networks
172.16.0.0/12
# IETF Protocol Assignments
192.0.0.0/24
# DS-Lite
192.0.0.0/29
# NAT64
192.0.0.170/32
# DNS64
192.0.0.171/32
# Documentation (TEST-NET-1)
192.0.2.0/24
# 6to4 Relay Anycast
192.88.99.0/24
# Private networks
192.168.0.0/16
# Benchmarking
198.18.0.0/15
# Documentation (TEST-NET-2)
198.51.100.0/24
# Documentation (TEST-NET-3)
203.0.113.0/24
# Reserved
240.0.0.0/4
# Limited Broadcast
255.255.255.255/32
```

This results in a pretty simple scan command, I'll save it as a configuration file, and then launch masscan under the screen program so I don't lose my progress.

`./masscan/bin/masscan --ports 1978 --source-port 6100 --excludefile exclude.conf --rate 1000000 -oL scan.txt --banners 0.0.0.0/0 --echo > scan.conf`

For some reason, it kept outputting `nocatpure = servername` into the configuration which produces an error, and wouldn't save the `excludefile = exclude.conf` to the configuration file. I had to make those two changes manually (`sed -i 's/nocapture = servername/excludefile = exclude.conf/' scan.conf`), and we were up and running.

Then in a screen session we can execute the actual scan:

`sudo ./masscan/bin/masscan --conf scan.conf`

Finally, we can parse the output list to an input list for Nmap by getting the fourth field of every line: `cut -d\  -f4 scan.txt > IPs.txt`. Then use Nmap with our custom service scanner:

`sudo nmap -sV -p1978 -iL IPs.txt --versiondb ./scanning/nmap-remotemouse-probe` 

From there you can simply grep your results and start hacking :).


## Masscan

Building a masscan module actually took a little bit of work, and effort (ugh, I know, right?). I ended up reading a lot of the `proto-ftp.c` code in order to see how it parsed the FTP protocol, and how it "told" the scanner of its existence. Through that, I was able to create a `proto-remotemouse.c` that parsed the banner from port 1978 and determined the OS (again, technically not sure if that is supposed to be `win` vs `mac`, but I'm going to guess yes for now), and if the service is password protected.

Now, you are no longer encumbered by Nmap's speed hit, you can freely scan the internet using the beauty of masscan.


For anyone looking to extend Masscan here is basically what you have to do:

### Extending Masscan

This is probably super wrong, and will make the masscan developers cringe, but it worked for me:

1. Add a new entry to the `enum ApplicationProtocol` in `masscan-app.h`
    
    This is basically the global variable for "Hey I want to be able to plug this into different places"
2. Create a App->String and String->App mapping in `masscan_app_to_string` and `masscan_string_to_app`.

    This is helps masscan later on translate your protocol to a friendly string for the banners
3. Include your protocol's header in `proto-banner1.c`
4. Add a new entry into `struct Patterns patterns[]` in `proto-banner1.c`.
5. Add a new `case` to the `switch (tcb_state->app_proto)` statement in the `banner1_parse` function.
6. Call your `parse` function in the aforementioned `case` statement.
7. Create a new file for your protocol, include a custom `ProtocolParserStream` declaration.

    This is a little more complicated, but you'll want an `init`, `parse`, and `selftest` function declared for the protocol.
8. Create a parser function.

    Your parser function will handle the logic of actually parsing a banner for information. The `px` parameter contains the banner, and the `length` parameter holds the length of `px`.



### Legal Stuff

Because masscan has a `GNU Affero General Public License version 3` license, I think even though I technically don't have to since I'm not re-distributing the source, I'm going to put the patch under that license and explain a few legal aspects:


To install masscan, follow the instructions below:

```bash
sudo apt-get --assume-yes install git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
```

To install the patch I created in order to analyze the RemoteMouse protocol, follow the instructions below:

```bash

# From inside the masscan directory
git apply remote-mouse.patch
```

The masscan source code can be found here: https://github.com/robertdavidgraham/masscan

The patch is distrubuted under the GNU Affero General Public License version 3 license.