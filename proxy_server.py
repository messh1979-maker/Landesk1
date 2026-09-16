#!/usr/bin/env python3
"""
proxy_server.py - Rendezvous / relay server for the lan-desk prototype.

Run this on a machine BOTH the host and the viewer can reach (a box on
your LAN, or a small VPS). It only understands a two-line handshake:

    HOST <code>\n      -> registers a waiting host under <code>
    VIEW <code>\n      -> looks up a waiting host and pairs with it

Once paired, the proxy stops parsing anything -- it just relays raw
bytes between the two sockets in both directions. All the screen/
mouse/keyboard protocol lives in host.py and viewer.py, not here.

Usage:
    python proxy_server.py --host 0.0.0.0 --port 5000
"""
import argparse
import socket
import threading
import time

BUF_SIZE = 64 * 1024

# code -> waiting host socket
waiting_hosts = {}
waiting_lock = threading.Lock()

# --------------------- Rate limiting for VIEW (wrong-code) attempts ---------------------
# A 6-digit code only has ~1M possibilities, so guessing must be made
# expensive. This locks out an IP after too many failed VIEW attempts
# in a short window. It's IP-based, which is a reasonable prototype-
# level defense but not bulletproof (shared IPs, IP rotation) -- see
# the README's security section for the stronger fix (SAS/QR pairing).
RATE_LIMIT_MAX_ATTEMPTS = 3
RATE_LIMIT_WINDOW = 60      # seconds -- failures must fall in this window to count together
RATE_LIMIT_LOCKOUT = 300    # seconds -- how long an IP is locked out once it trips the limit

# ip -> {"count": int, "window_start": float, "locked_until": float}
view_attempts = {}
view_attempts_lock = threading.Lock()


def is_rate_limited(ip):
    now = time.monotonic()
    with view_attempts_lock:
        state = view_attempts.get(ip)
        return state is not None and state["locked_until"] > now


def record_view_failure(ip):
    now = time.monotonic()
    with view_attempts_lock:
        state = view_attempts.get(ip)
        if state is None or now - state["window_start"] > RATE_LIMIT_WINDOW:
            state = {"count": 0, "window_start": now, "locked_until": 0}
        state["count"] += 1
        if state["count"] >= RATE_LIMIT_MAX_ATTEMPTS:
            state["locked_until"] = now + RATE_LIMIT_LOCKOUT
            print(
                f"[proxy] {ip} locked out for {RATE_LIMIT_LOCKOUT}s "
                f"after {state['count']} failed VIEW attempts"
            )
        view_attempts[ip] = state


def record_view_success(ip):
    with view_attempts_lock:
        view_attempts.pop(ip, None)


def read_line(sock, max_len=256):
    """Read a single '\n'-terminated line (used only for the handshake)."""
    data = b""
    while len(data) < max_len:
        chunk = sock.recv(1)
        if not chunk:
            return None
        if chunk == b"\n":
            return data.decode("utf-8", errors="replace").strip()
        data += chunk
    return None


def relay(a, b, label):
    try:
        while True:
            chunk = a.recv(BUF_SIZE)
            if not chunk:
                break
            b.sendall(chunk)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        print(f"[proxy] relay ended ({label})")


def handle_connection(conn, addr):
    conn.settimeout(15)
    try:
        line = read_line(conn)
    except socket.timeout:
        conn.close()
        return

    if not line:
        conn.close()
        return

    parts = line.split(" ", 1)
    if len(parts) != 2:
        conn.close()
        return

    role, code = parts[0].upper(), parts[1].strip()

    if role == "HOST":
        with waiting_lock:
            if code in waiting_hosts:
                conn.sendall(b"ERR code_in_use\n")
                conn.close()
                return
            waiting_hosts[code] = conn
        conn.settimeout(None)
        try:
            conn.sendall(b"OK waiting_for_viewer\n")
        except OSError:
            with waiting_lock:
                waiting_hosts.pop(code, None)
        print(f"[proxy] host registered code={code} from {addr}")

    elif role == "VIEW":
        ip = addr[0]
        if is_rate_limited(ip):
            conn.sendall(b"ERR rate_limited\n")
            conn.close()
            print(f"[proxy] rejected VIEW from {addr} (rate limited)")
            return

        with waiting_lock:
            host_conn = waiting_hosts.pop(code, None)
        if host_conn is None:
            record_view_failure(ip)
            conn.sendall(b"ERR no_such_host\n")
            conn.close()
            return

        record_view_success(ip)
        conn.settimeout(None)
        try:
            conn.sendall(b"OK paired\n")
            host_conn.sendall(b"OK paired\n")
        except OSError:
            conn.close()
            host_conn.close()
            return
        print(f"[proxy] paired viewer {addr} with host code={code}")
        t1 = threading.Thread(target=relay, args=(host_conn, conn, "host->viewer"), daemon=True)
        t2 = threading.Thread(target=relay, args=(conn, host_conn, "viewer->host"), daemon=True)
        t1.start()
        t2.start()
    else:
        conn.sendall(b"ERR bad_role\n")
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(50)
    print(f"[proxy] listening on {args.host}:{args.port}")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
