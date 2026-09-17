#!/usr/bin/env python3
"""
viewer.py - connects to the proxy with a host's connection code, runs
an end-to-end encrypted handshake with the host (see secure_channel.py
-- the proxy never sees the key), and shows/controls that host's
screen over the encrypted channel.

After pairing this prints a 6-digit SAS in the window title. Compare
it with the code the host prints before you trust the session -- if
they don't match, someone may be intercepting the connection (even a
malicious proxy can't make them match, since it can't compute the
shared secret without the private keys).

Usage:
    python viewer.py --proxy-host 203.0.113.10 --proxy-port 5000 --code 123456
"""
import argparse
import socket
import struct
import threading
import tkinter as tk

import av
from PIL import ImageTk

from secure_channel import SecureChannel, HandshakeError

MSG_FRAME = 0x01
MSG_MOUSE_MOVE = 0x02
MSG_MOUSE_CLICK = 0x03
MSG_KEY = 0x04
MSG_SCROLL = 0x05


class Viewer:
    def __init__(self, channel):
        self.channel = channel
        self.stop_event = threading.Event()

        self.root = tk.Tk()
        self.root.title(f"lan-desk viewer  —  verify code: {channel.sas}")
        self.label = tk.Label(self.root)
        self.label.pack()
        self.tk_img = None  # keep a reference or Tk garbage-collects the image

        self.label.bind("<Motion>", self.on_move)
        self.label.bind("<ButtonPress-1>", lambda e: self.on_click(0, 1))
        self.label.bind("<ButtonRelease-1>", lambda e: self.on_click(0, 0))
        self.label.bind("<ButtonPress-3>", lambda e: self.on_click(1, 1))
        self.label.bind("<ButtonRelease-3>", lambda e: self.on_click(1, 0))
        self.label.bind("<MouseWheel>", self.on_scroll)               # Windows/Mac
        self.label.bind("<Button-4>", lambda e: self.send_scroll(0, 1))   # Linux wheel up
        self.label.bind("<Button-5>", lambda e: self.send_scroll(0, -1))  # Linux wheel down
        self.root.bind("<KeyPress>", lambda e: self.on_key(e, 1))
        self.root.bind("<KeyRelease>", lambda e: self.on_key(e, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.last_img_size = (1, 1)
        # One decoder for the whole session: H.265 frames are inter-coded
        # (P-frames reference earlier frames), so they must be fed to the
        # same decoder in order, not decoded independently like JPEGs.
        self.decoder = av.CodecContext.create("hevc", "r")

        threading.Thread(target=self.recv_loop, daemon=True).start()

    def send_msg(self, msg_type, payload=b""):
        try:
            self.channel.send(msg_type, payload)
        except OSError:
            self.stop_event.set()

    def on_move(self, event):
        w, h = self.last_img_size
        if w <= 1 or h <= 1:
            return
        nx = max(0, min(65535, int(event.x / w * 65535)))
        ny = max(0, min(65535, int(event.y / h * 65535)))
        self.send_msg(MSG_MOUSE_MOVE, struct.pack("!II", nx, ny))

    def on_click(self, button, pressed):
        self.send_msg(MSG_MOUSE_CLICK, bytes([button, pressed]))

    def on_scroll(self, event):
        direction = 1 if event.delta > 0 else -1
        self.send_scroll(0, direction)

    def send_scroll(self, dx, dy):
        self.send_msg(MSG_SCROLL, struct.pack("!hh", dx, dy))

    def on_key(self, event, pressed):
        key = self.tk_keysym_to_pyautogui(event.keysym)
        if not key:
            return
        self.send_msg(MSG_KEY, bytes([pressed]) + key.encode("utf-8"))

    @staticmethod
    def tk_keysym_to_pyautogui(keysym):
        # Small mapping covering the common special keys; single printable
        # characters pass through unchanged. Extend this table as you hit
        # keys it doesn't know about yet.
        mapping = {
            "Return": "enter", "BackSpace": "backspace", "Escape": "esc",
            "Tab": "tab", "space": "space", "Left": "left", "Right": "right",
            "Up": "up", "Down": "down", "Shift_L": "shift", "Shift_R": "shift",
            "Control_L": "ctrl", "Control_R": "ctrl", "Alt_L": "alt", "Alt_R": "alt",
            "Delete": "delete", "Home": "home", "End": "end",
            "Prior": "pageup", "Next": "pagedown",
        }
        if keysym in mapping:
            return mapping[keysym]
        if len(keysym) == 1:
            return keysym
        return None

    def recv_loop(self):
        while not self.stop_event.is_set():
            try:
                msg_type, payload = self.channel.recv()
            except HandshakeError as e:
                print(f"[viewer] secure channel error, closing session: {e}")
                self.stop_event.set()
                break

            if msg_type is None:
                print("[viewer] connection closed")
                self.stop_event.set()
                break
            if msg_type == MSG_FRAME:
                try:
                    packet = av.Packet(payload)
                    for frame in self.decoder.decode(packet):
                        img = frame.to_image()
                        self.last_img_size = img.size
                        self.root.after(0, self.update_image, img)
                except Exception as e:
                    # A garbled/incomplete packet can make the decoder log a
                    # warning and skip it -- normal on a lossy transport,
                    # fine to ignore here since we're on reliable TCP.
                    print(f"[viewer] decode error: {e}")

    def update_image(self, img):
        self.tk_img = ImageTk.PhotoImage(img)
        self.label.configure(image=self.tk_img)

    def on_close(self):
        self.stop_event.set()
        try:
            self.channel.sock.close()
        except OSError:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy-host", required=True)
    ap.add_argument("--proxy-port", type=int, default=5000)
    ap.add_argument("--code", required=True, help="6-digit code shown by the host")
    args = ap.parse_args()

    sock = socket.create_connection((args.proxy_host, args.proxy_port), timeout=10)
    sock.settimeout(None)
    sock.sendall(f"VIEW {args.code}\n".encode())
    reply = sock.recv(1024)
    if not reply.startswith(b"OK"):
        print(f"[viewer] could not connect: {reply!r}")
        return

    try:
        channel = SecureChannel.handshake_as_viewer(sock)
    except (HandshakeError, OSError) as e:
        print(f"[viewer] E2EE handshake failed: {e}")
        return

    print("[viewer] paired with host.")
    print(f"[viewer] verify this matches the host's printed code: {channel.sas}")
    print("[viewer] opening window...")
    Viewer(channel).run()


if __name__ == "__main__":
    main()
