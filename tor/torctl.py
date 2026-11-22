#!/usr/bin/env python3
"""Minimal Tor control-port client: NEWNYM + GETINFO status/circuit-established.

Auth: cookie (CookieAuthentication 1), cookie file read as root.
"""
import os
import socket
import sys
import time
import binascii

HOST = "127.0.0.1"
PORT = 9051
COOKIE_CANDIDATES = [
    "/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
]
COOKIE = next((p for p in COOKIE_CANDIDATES if os.path.exists(p)), COOKIE_CANDIDATES[0])


def send_cmd(sock, cmd):
    sock.sendall((cmd + "\r\n").encode())
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="replace").strip()


def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    with open(COOKIE, "rb") as f:
        cookie = binascii.hexlify(f.read()).decode()
    resp = send_cmd(s, "AUTHENTICATE " + cookie)
    if not resp.startswith("250"):
        raise RuntimeError("auth failed: " + resp)
    return s


def newnym(wait=6.0):
    s = connect()
    for attempt in range(5):
        resp = send_cmd(s, "SIGNAL NEWNYM")
        if resp.startswith("250"):
            break
        # 550 = rate limited ("Too many new identity requests")
        time.sleep(5)
    s.close()
    time.sleep(wait)


def getinfo(key):
    s = connect()
    resp = send_cmd(s, "GETINFO " + key)
    s.close()
    return resp


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "newnym"
    if action == "newnym":
        wait = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0
        newnym(wait)
        print("NEWNYM sent")
    elif action == "status":
        print(getinfo("status/bootstrap-phase"))
        print(getinfo("status/circuit-established"))
    else:
        sys.exit("unknown action")
