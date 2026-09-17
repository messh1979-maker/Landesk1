#!/usr/bin/env python3
"""
host.py - runs on the machine you want to control remotely.

Connects OUT to the proxy (so it works from behind NAT with no port
forwarding needed), registers a random 6-digit code, then -- once a
viewer pairs -- runs an end-to-end encrypted handshake directly with
that viewer (see secure_channel.py; the proxy never sees the key) and
streams the screen as a real H.265 (HEVC) video stream via PyAV/
libx265, applying the mouse/keyboard commands it receives back.

Only run this on a machine you own or are explicitly authorized to
control, and only give the code out to people you trust. After
pairing, this prints a 6-digit SAS -- read it to the person on the
viewer side (or send it over a channel you trust) and make sure it
matches what their window shows before you assume the connection is
safe. See the README for the full security notes.

Usage:
    python host.py --proxy-host 203.0.113.10 --proxy-port 5000 \
        --bitrate 256000 --fps 8 --max-dim 960
"""
import argparse
import secrets
import socket
import struct
import threading
import time
from fractions import Fraction

import av
import mss
import pyautogui
from PIL import Image

from secure_channel import SecureChannel, HandshakeError

pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0

MSG_FRAME = 0x01
MSG_MOUSE_MOVE = 0x02
MSG_MOUSE_CLICK = 0x03
MSG_KEY = 0x04
MSG_SCROLL = 0x05


def make_encoder(width, height, fps, bitrate):
    """
    One H.265 encoder per session. libx265 with preset=ultrafast and
    tune=zerolatency trades compression efficiency for low latency and
    low CPU cost, which matters more than raw quality for remote
    control. keyint/min-keyint force a keyframe roughly every 2 seconds
    so a viewer that just joined (or that dropped a packet, on a future
    lossy transport) can recover quickly; bframes=0 avoids the extra
    buffering delay B-frames would add.
    """
    encoder = av.CodecContext.create("libx265", "w")
    encoder.width = width
    encoder.height = height
    encoder.pix_fmt = "yuv420p"
    encoder.framerate = Fraction(fps, 1)
    encoder.time_base = Fraction(1, fps)
    encoder.bit_rate = bitrate
    encoder.options = {
        "preset": "ultrafast",
        "tune": "zerolatency",
        "x265-params": f"keyint={fps * 2}:min-keyint=1:bframes=0",
    }
    return encoder


def screen_sender(channel, stop_event, fps, bitrate, max_dim):
    frame_interval = 1.0 / fps
    encoder = None
    pts = 0

    with mss.mss() as sct:
        monitor = sct.monitors[1]
        while not stop_event.is_set():
            start = time.monotonic()
            try:
                shot = sct.grab(monitor)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")

                scale = min(1.0, max_dim / max(img.size))
                tw = max(2, int(img.width * scale))
                th = max(2, int(img.height * scale))
                # yuv420p needs even dimensions (chroma is subsampled 2x2)
                tw -= tw % 2
                th -= th % 2
                if (tw, th) != img.size:
                    img = img.resize((tw, th), Image.BILINEAR)

                if encoder is None:
                    encoder = make_encoder(tw, th, fps, bitrate)
                    print(f"[host] H.265 encoder ready: {tw}x{th} @ {fps}fps, {bitrate}bps")

                frame = av.VideoFrame.from_image(img).reformat(format="yuv420p")
                frame.pts = pts
                pts += 1

                for packet in encoder.encode(frame):
                    channel.send(MSG_FRAME, packet.to_bytes())
            except OSError:
                stop_event.set()
                break
            except Exception as e:
                print(f"[host] frame capture/encode error: {e}")

            elapsed = time.monotonic() - start
            if elapsed < frame_interval:
                time.sleep(frame_interval - elapsed)

    if encoder is not None:
        try:
            for packet in encoder.encode(None):  # flush
                channel.send(MSG_FRAME, packet.to_bytes())
        except Exception:
            pass


def denormalize(nx, ny, screen_w, screen_h):
    x = int(nx / 65535 * (screen_w - 1))
    y = int(ny / 65535 * (screen_h - 1))
    return max(0, min(screen_w - 1, x)), max(0, min(screen_h - 1, y))


def input_receiver(channel, stop_event, screen_w, screen_h):
    button_names = {0: "left", 1: "right", 2: "middle"}
    while not stop_event.is_set():
        try:
            msg_type, payload = channel.recv()
        except HandshakeError as e:
            print(f"[host] secure channel error, closing session: {e}")
            stop_event.set()
            break

        if msg_type is None:
            print("[host] connection closed by proxy/viewer")
            stop_event.set()
            break

        try:
            if msg_type == MSG_MOUSE_MOVE and len(payload) == 8:
                nx, ny = struct.unpack("!II", payload)
                x, y = denormalize(nx, ny, screen_w, screen_h)
                pyautogui.moveTo(x, y)

            elif msg_type == MSG_MOUSE_CLICK and len(payload) == 2:
                button, pressed = payload[0], payload[1]
                name = button_names.get(button, "left")
                if pressed:
                    pyautogui.mouseDown(button=name)
                else:
                    pyautogui.mouseUp(button=name)

            elif msg_type == MSG_KEY and len(payload) >= 1:
                pressed = payload[0]
                key = payload[1:].decode("utf-8", errors="ignore")
                if not key:
                    continue
                try:
                    if pressed:
                        pyautogui.keyDown(key)
                    else:
                        pyautogui.keyUp(key)
                except Exception:
                    pass  # unmapped key name -- extend the viewer's key table

            elif msg_type == MSG_SCROLL and len(payload) == 4:
                dx, dy = struct.unpack("!hh", payload)
                pyautogui.hscroll(dx)
                pyautogui.scroll(dy)

        except Exception as e:
            print(f"[host] failed to apply input: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", required=True)
    ap.add_argument("--proxy-port", type=int, default=5000)
    ap.add_argument("--bitrate", type=int, default=256_000, help="target H.265 bitrate, bits/sec")
    ap.add_argument("--fps", type=int, default=8)
    ap.add_argument("--max-dim", type=int, default=960, help="longest side, in pixels, sent to the viewer")
    args = ap.parse_args()

    screen_w, screen_h = pyautogui.size()

    while True:
        code = str(secrets.randbelow(10**6)).zfill(6)
        try:
            sock = socket.create_connection((args.proxy_host, args.proxy_port), timeout=10)
            sock.settimeout(None)
            sock.sendall(f"HOST {code}\n".encode())
            reply = sock.recv(1024)
            if not reply.startswith(b"OK"):
                print(f"[host] registration failed: {reply!r}")
                sock.close()
                time.sleep(3)
                continue
        except OSError as e:
            print(f"[host] cannot reach proxy: {e}")
            time.sleep(3)
            continue

        print("=" * 40)
        print(f"  Your connection code: {code}")
        print("=" * 40)
        print("[host] waiting for a viewer to connect...")

        # Blocks here until a viewer pairs (proxy sends a second "OK" line)
        try:
            paired = sock.recv(1024)
        except OSError:
            sock.close()
            continue
        if not paired.startswith(b"OK"):
            sock.close()
            continue

        try:
            channel = SecureChannel.handshake_as_host(sock)
        except (HandshakeError, OSError) as e:
            print(f"[host] E2EE handshake failed: {e}")
            sock.close()
            continue

        print("=" * 40)
        print(f"  Verify this matches the viewer's code: {channel.sas}")
        print("  (read it out, or confirm over a channel you trust --")
        print("   if it doesn't match, someone may be intercepting you)")
        print("=" * 40)
        print("[host] viewer connected. Streaming H.265 (encrypted)...")

        stop_event = threading.Event()
        t_send = threading.Thread(
            target=screen_sender,
            args=(channel, stop_event, args.fps, args.bitrate, args.max_dim),
            daemon=True,
        )
        t_recv = threading.Thread(
            target=input_receiver, args=(channel, stop_event, screen_w, screen_h), daemon=True
        )
        t_send.start()
        t_recv.start()
        t_send.join()
        t_recv.join()
        sock.close()
        print("[host] session ended, restarting...")


if __name__ == "__main__":
    main()
