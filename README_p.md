# lan-desk prototype

A minimal, clean rebuild of the `proxy / host / viewer` architecture from
your `lan-desk` repo: a host behind NAT connects *out* to a reachable
proxy, gets a 6-digit code, and a viewer uses that code to pair through
the proxy and remote-control the host's screen.

Three files, three roles:

- `proxy_server.py` — dumb relay. Understands only the pairing handshake
  (`HOST <code>` / `VIEW <code>`), then copies raw bytes between the two
  sockets. Doesn't know or care what's inside them.
- `host.py` — runs on the machine being controlled. Captures the screen
  with `mss`, encodes it as a real **H.265 (HEVC)** video stream with
  `PyAV`/`libx265` (not per-frame JPEGs), streams it out, and applies
  incoming mouse/keyboard commands with `pyautogui`.
- `viewer.py` — a small Tkinter window. Decodes the H.265 stream and
  shows it, and forwards your mouse/keyboard events back to the host.

Stack: plain Python 3 stdlib sockets + `mss` + `Pillow` + `pyautogui` +
`PyAV` (libx265/HEVC encode+decode) + `tkinter` (stdlib). No external
services, no build step — this is meant to be readable and easy to
modify, not maximally optimized.

### Why H.265 instead of per-frame JPEG

This is the single biggest bandwidth win available: JPEG compresses
each frame independently, so it pays the full cost of the image every
single frame. H.265 is a *video* codec — most frames only encode what
changed since the previous one (inter-frame / P-frame prediction),
which is exactly what a mostly-static desktop needs. `host.py` targets
256kbps by default (`--bitrate`), uses `preset=ultrafast` +
`tune=zerolatency` to keep encoding latency low, and forces a keyframe
roughly every 2 seconds (`keyint`) so quality recovers quickly after
any change. `viewer.py` keeps one decoder alive for the whole session,
since H.265 frames must be decoded in order, not one-off like JPEGs.

## How to run it

You need three terminals (they can be on three different machines, or
all on one machine for testing).

1. **Install dependencies** on the host and viewer machines:
   ```
   pip install -r requirements.txt
   ```
   Tkinter ships with Python on Windows/macOS. On Linux you may need:
   ```
   sudo apt install python3-tk
   ```
   `pip install av` pulls prebuilt wheels with libx265 bundled on most
   platforms (Windows/macOS/manylinux). If a wheel isn't available for
   your platform and it tries to build from source, you'll also need
   ffmpeg's dev headers with libx265 enabled (e.g. `sudo apt install
   libavcodec-dev libavformat-dev libavutil-dev libswscale-dev` on
   Debian/Ubuntu, then `pip install av --no-binary av`).

2. **Start the proxy** on a machine both the host and viewer can reach
   (a LAN box, or any VPS):
   ```
   python proxy_server.py --host 0.0.0.0 --port 5000
   ```

3. **Start the host** on the machine you want to control, pointing it
   at the proxy's address:
   ```
   python host.py --proxy-host <proxy-ip> --proxy-port 5000 \
       --bitrate 256000 --fps 8 --max-dim 960
   ```
   It prints a 6-digit code and waits. `--bitrate`/`--fps`/`--max-dim`
   are tunable — the defaults target the 256kbps case; on a better link
   you can push `--bitrate` and `--max-dim` up.

4. **Start the viewer** on the controlling machine, with that code:
   ```
   python viewer.py --proxy-host <proxy-ip> --proxy-port 5000 --code 123456
   ```
   A window opens showing the host's screen; mouse and keyboard on that
   window control the host.

To test everything on one machine, just run all three commands in
separate terminals with `--proxy-host 127.0.0.1`.

## Important: this is a prototype, not a secure tool yet

Right now, anyone who reaches the proxy and knows (or is told) the
6-digit code gets full mouse/keyboard control of the host, in plain
text, with no further authentication. The proxy does rate-limit *wrong*
code guesses per IP (3 failed `VIEW` attempts within 60s locks that IP
out for 5 minutes — see `RATE_LIMIT_*` in `proxy_server.py`), so brute
forcing the 6-digit code isn't free, but that's a floor, not a fix: the
stream itself is still unencrypted TCP, and IP-based limiting doesn't
stop an attacker with many IPs. This is fine for a same-LAN demo
between machines you control — it is **not** safe to expose to the
public internet as-is. Treat it the way you'd treat an unauthenticated
admin port.

## What I'd extend first

1. **Encrypt and authenticate the connection.** Wrap the sockets in TLS
   (`ssl` module) so traffic isn't plaintext, and add a real shared
   secret (e.g. host and viewer both derive a key from a passphrase you
   set, not just a random 6-digit code) so pairing can't be guessed or
   sniffed.
2. **Rate-limit / expire codes.** *Done* — the proxy now locks out an
   IP after 3 failed `VIEW` attempts in 60s (see `RATE_LIMIT_*` in
   `proxy_server.py`). Next step here: also expire an unclaimed `HOST`
   registration after a couple of minutes instead of leaving it
   waiting forever, and consider a global (not just per-IP) attempt
   counter per code, since per-IP alone doesn't stop a distributed
   guesser.
3. **Adaptive bitrate.** `--bitrate`/`--fps`/`--max-dim` are fixed for
   the whole session right now. Add a feedback loop (viewer reports
   measured throughput/decode latency back over a control message,
   host adjusts `encoder.bit_rate` and re-creates the encoder, or
   switches to CBR-style rate control) — this is exactly what the
   bandwidth-probe logic in your `host_v2.py` was doing for JPEG
   quality, just retargeted at the H.265 encoder's bitrate.
4. **Hardware-accelerated encode** (NVENC/QuickSync/AMF via PyAV's
   `hevc_nvenc`/`hevc_qsv`/`hevc_amf` codec names) when available on
   the host, falling back to `libx265` otherwise — much lower CPU use
   at the same bitrate.
5. **Clipboard sync and file transfer**, which your original repo had —
   add new message types (`MSG_CLIPBOARD`, `MSG_FILE_CHUNK`) following
   the same length-prefixed framing already in `host.py`/`viewer.py`.
6. **Multi-monitor support** — `host.py` currently always grabs
   `sct.monitors[1]` (the first physical monitor); add a monitor picker
   and send its index/resolution to the viewer.
7. **Reconnect/resilience** on the viewer side to match the host's
   retry loop, and a "waiting room" UI instead of a blank window while
   pairing.
