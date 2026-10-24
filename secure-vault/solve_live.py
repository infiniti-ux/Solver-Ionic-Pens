#!/usr/bin/env python3
"""End-to-end PoC: request a fresh record, recover SIDH, decrypt and submit it.

Required environment variables:
  SIDH_REPO   path to cloned Breaking-SIDH/direct-attack repository
  SAGE_BIN    Sage executable (default: `sage`)
"""
import base64
import os
import re
import socket
import subprocess
import threading
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

HERE = Path(__file__).resolve().parent
HOST = os.environ.get("CHRONOS_HOST", "chall.ctf.tccpens.id")
PORT = int(os.environ.get("CHRONOS_PORT", "30818"))
REPO = Path(os.environ.get("SIDH_REPO", HERE / "direct-attack")).resolve()
SAGE = os.environ.get("SAGE_BIN", "sage")
RECORD = Path(os.environ.get("CHRONOS_RECORD", HERE / "r_live.bin")).resolve()
RECOVER_SAGE = HERE / "recover_sidh.sage"
SHARED_SAGE = HERE / "shared_j.sage"


def recv_until(sock, marker=b"Choice: ", timeout=30):
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def read_varint(buf, pos):
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, pos
        shift += 7


def fields(buf):
    out, pos = [], 0
    while pos < len(buf):
        tag, pos = read_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if wire == 2:
            size, pos = read_varint(buf, pos)
            value = buf[pos:pos + size]
            pos += size
        elif wire == 0:
            value, pos = read_varint(buf, pos)
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire}")
        out.append((field, value))
    return out


def run_sage(path, *, record, secret=None):
    env = os.environ.copy()
    env["SIDH_REPO"] = str(REPO)
    env["CHRONOS_RECORD"] = str(record)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    if secret is not None:
        env["CHRONOS_SECRET"] = str(secret)
    result = subprocess.run(
        [SAGE, str(path)], cwd=HERE, env=env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=600,
    )
    if result.returncode:
        # Keep logs visible; a failed Sage stage is not silently ignored.
        print(result.stdout, flush=True)
        raise RuntimeError(f"Sage stage failed: {path.name} (exit {result.returncode})")
    return result.stdout


def keepalive_worker(sock, stop, state, lock):
    # Sage can take ~1–2 minutes. Blank menu input is harmless and keeps the
    # session-bound TCP connection alive until the recovered payload is ready.
    while not stop.wait(10):
        try:
            sock.sendall(b"\n")
            with lock:
                state["count"] += 1
        except OSError as exc:
            print("keepalive stopped:", exc, flush=True)
            return


def drain_keepalives(sock, count):
    """Consume menu responses to keepalive newlines; tolerate short reads."""
    if count <= 0:
        return
    sock.settimeout(3)
    seen = 0
    try:
        while seen < count:
            chunk = sock.recv(8192)
            if not chunk:
                break
            seen += chunk.count(b"Choice: ")
    except socket.timeout:
        # Any remaining menu output will be consumed by recv_until() for >.
        pass


def main():
    if not REPO.is_dir():
        raise SystemExit(
            f"SIDH repo not found: {REPO}\n"
            "Set SIDH_REPO to the clone of Breaking-SIDH/direct-attack."
        )

    sock = socket.create_connection((HOST, PORT), timeout=15)
    stop = threading.Event()
    keep_state = {"count": 0}
    keep_lock = threading.Lock()
    worker = None
    try:
        banner = recv_until(sock)
        print(banner.decode("utf-8", "replace"), flush=True)

        # Option 1 returns a Base64-wrapped protobuf record.
        sock.sendall(b"1\n")
        response = recv_until(sock)
        match = re.search(
            rb"-----BEGIN CHRONOS RECORD-----(.*?)-----END CHRONOS RECORD-----",
            response, re.S,
        )
        if not match:
            raise RuntimeError("Could not extract the Chronos record from option 1")
        record = base64.b64decode(b"".join(match.group(1).split()))
        RECORD.parent.mkdir(parents=True, exist_ok=True)
        RECORD.write_bytes(record)
        meta = dict(fields(dict(fields(record))[1]))
        print(f"Fetched {len(record)} bytes; session_id={meta[1].decode()}", flush=True)
        print("Saved record:", RECORD, flush=True)

        # Start keepalives only after option 1 returned to the menu.
        worker = threading.Thread(
            target=keepalive_worker,
            args=(sock, stop, keep_state, keep_lock),
            daemon=True,
        )
        worker.start()

        # 1) Recover the small 3^19 SIDH secret using the direct attack.
        attack_log = run_sage(RECOVER_SAGE, record=RECORD)
        print("=== SIDH attack ===\n" + attack_log, flush=True)
        sm = re.search(r"Secret key recovered:\s*(\d+)", attack_log)
        if not sm:
            raise RuntimeError("The direct attack did not print a recovered scalar")
        secret = int(sm.group(1))

        # 2) Apply that scalar to the companion public key to obtain j(E_shared).
        shared_log = run_sage(SHARED_SAGE, record=RECORD, secret=secret)
        print("=== Shared invariant ===\n" + shared_log, flush=True)
        jm = re.search(r"j c0=\s*(\d+)\s+c1=\s*(\d+)", shared_log)
        if not jm:
            raise RuntimeError("Could not parse j_re and j_im from Sage output")
        j_re, j_im = map(int, jm.groups())

        # 3) HKDF-SHA256 -> AES-256-GCM, using the values from archive field 6.
        outer = dict(fields(record))
        archive = dict(fields(outer[6]))
        ikm = j_re.to_bytes(32, "big") + j_im.to_bytes(32, "big")
        key = HKDF(ikm, 32, archive[4], SHA256, context=archive[5])
        plaintext = AES.new(
            key, AES.MODE_GCM, nonce=archive[2], mac_len=16
        ).decrypt_and_verify(archive[1], archive[3])
        plaintext.decode("utf-8")
        out = HERE / "archive_plaintext_live.bin"
        out.write_bytes(plaintext)
        print(f"recovered scalar={secret}", flush=True)
        print(f"j_re={j_re}\nj_im={j_im}", flush=True)
        print("plaintext:", plaintext.decode("utf-8"), flush=True)
        print("saved plaintext:", out, flush=True)

        # Stop the keepalive thread. Keep the SAME socket for option 2; this
        # service binds each archive to the connection that issued its record.
        stop.set()
        worker.join(timeout=12)
        drain_keepalives(sock, keep_state["count"])

        # Service accepts Base64 (prompt says hex or Base64). Submit the exact
        # plaintext bytes recovered from this connection's record.
        sock.sendall(b"2\n")
        prompt = recv_until(sock, b"> ")
        print(prompt.decode("utf-8", "replace"), flush=True)
        sock.sendall(base64.b64encode(plaintext) + b"\n")
        result = recv_until(sock)
        text = result.decode("utf-8", "replace")
        print(text, flush=True)
        if "Verification failed" in text:
            raise RuntimeError("Service rejected the recovered archive")
        if "flag" not in text.lower():
            print("Note: no flag text detected; inspect the service response above.")
    finally:
        stop.set()
        if worker is not None:
            worker.join(timeout=2)
        sock.close()


if __name__ == "__main__":
    main()
