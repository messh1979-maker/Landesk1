"""
secure_channel.py - end-to-end encrypted channel for lan-desk.

Runs a single X25519 ECDH handshake over the (already proxy-paired) raw
socket, derives two *directional* AEAD keys with HKDF (one per
direction, so the two sides never reuse a nonce under the same key),
and after that wraps every application message (MSG_FRAME,
MSG_MOUSE_MOVE, ...) in ChaCha20-Poly1305.

The proxy only ever sees this ciphertext blob. It never sees the
session key, so it cannot decrypt the stream even if fully
compromised -- that's the "not even the proxy" part of E2EE.

It also produces a Short Authentication String (SAS): a 6-digit code
both sides compute from the shared secret and must compare out of
band (read it out loud, message it on a channel you trust, etc). If a
man-in-the-middle -- the proxy or anyone else -- tried to negotiate a
separate key with each side instead of letting them talk directly, the
SAS on the two ends would NOT match. Plain ECDH alone can't catch
that; the SAS is what does.

Note on nonces: this assumes the underlying transport is reliable and
ordered (TCP, as in this prototype), so a simple incrementing counter
per direction is safe as a nonce and doubles as replay/reorder
protection (a message decrypted out of counter order will fail
authentication and the channel is torn down). If you migrate to an
unordered/lossy transport (e.g. WebRTC/UDP in a later phase), this
counter scheme needs to become an explicit per-packet sequence number
carried alongside the ciphertext instead.
"""
import hashlib
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HELLO_MAGIC = b"LD01"  # protocol/version tag exchanged in the clear
KEY_LEN = 32
MAX_CIPHERTEXT = 8 * 1024 * 1024


class HandshakeError(Exception):
    pass


class ChannelClosed(Exception):
    pass


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ChannelClosed()
        buf.extend(chunk)
    return bytes(buf)


def _send_pubkey(sock, pub_bytes):
    sock.sendall(HELLO_MAGIC + struct.pack("!I", len(pub_bytes)) + pub_bytes)


def _recv_pubkey(sock):
    magic = _recv_exact(sock, 4)
    if magic != HELLO_MAGIC:
        raise HandshakeError(f"bad hello magic: {magic!r}")
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    if length != KEY_LEN:
        raise HandshakeError(f"unexpected pubkey length: {length}")
    return _recv_exact(sock, length)


def _sas_from_secret(shared_secret, pub_a, pub_b):
    """6-digit SAS from the shared secret + both pubkeys, order-independent
    so host and viewer compute the exact same value."""
    ordered = b"".join(sorted([pub_a, pub_b]))
    digest = hashlib.sha256(shared_secret + ordered).digest()
    number = int.from_bytes(digest[:4], "big") % 1_000_000
    return str(number).zfill(6)


class SecureChannel:
    def __init__(self, sock, send_key, recv_key, sas):
        self.sock = sock
        self._aead_send = ChaCha20Poly1305(send_key)
        self._aead_recv = ChaCha20Poly1305(recv_key)
        self._send_counter = 0
        self._recv_counter = 0
        self._send_lock = threading.Lock()
        self.sas = sas

    @staticmethod
    def _derive_keys(shared_secret, pub_a, pub_b, label_a_to_b, label_b_to_a):
        ordered_salt = b"".join(sorted([pub_a, pub_b]))
        a_to_b = HKDF(
            algorithm=hashes.SHA256(), length=KEY_LEN, salt=ordered_salt,
            info=label_a_to_b,
        ).derive(shared_secret)
        b_to_a = HKDF(
            algorithm=hashes.SHA256(), length=KEY_LEN, salt=ordered_salt,
            info=label_b_to_a,
        ).derive(shared_secret)
        return a_to_b, b_to_a

    @classmethod
    def handshake_as_host(cls, sock):
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        _send_pubkey(sock, pub_bytes)
        peer_pub_bytes = _recv_pubkey(sock)
        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))

        host_to_viewer, viewer_to_host = cls._derive_keys(
            shared, pub_bytes, peer_pub_bytes,
            b"lan-desk host->viewer", b"lan-desk viewer->host",
        )
        sas = _sas_from_secret(shared, pub_bytes, peer_pub_bytes)
        return cls(sock, send_key=host_to_viewer, recv_key=viewer_to_host, sas=sas)

    @classmethod
    def handshake_as_viewer(cls, sock):
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        peer_pub_bytes = _recv_pubkey(sock)
        _send_pubkey(sock, pub_bytes)
        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))

        host_to_viewer, viewer_to_host = cls._derive_keys(
            shared, peer_pub_bytes, pub_bytes,
            b"lan-desk host->viewer", b"lan-desk viewer->host",
        )
        sas = _sas_from_secret(shared, peer_pub_bytes, pub_bytes)
        return cls(sock, send_key=viewer_to_host, recv_key=host_to_viewer, sas=sas)

    def send(self, msg_type, payload=b""):
        plaintext = struct.pack("!B", msg_type) + payload
        with self._send_lock:
            nonce = b"\x00\x00\x00\x00" + struct.pack("!Q", self._send_counter)
            self._send_counter += 1
            ciphertext = self._aead_send.encrypt(nonce, plaintext, None)
            self.sock.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)

    def recv(self):
        """Returns (msg_type, payload), or (None, None) on a clean close.
        Raises HandshakeError on a corrupted/tampered/replayed packet --
        treat that as fatal and tear the session down, don't try to
        resync."""
        try:
            (length,) = struct.unpack("!I", _recv_exact(self.sock, 4))
            if length > MAX_CIPHERTEXT:
                raise HandshakeError(f"ciphertext too large: {length}")
            ciphertext = _recv_exact(self.sock, length)
        except ChannelClosed:
            return None, None

        nonce = b"\x00\x00\x00\x00" + struct.pack("!Q", self._recv_counter)
        self._recv_counter += 1
        try:
            plaintext = self._aead_recv.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise HandshakeError(
                "message authentication failed (tampered, replayed, or "
                "out-of-order packet) -- closing the session"
            )
        return plaintext[0], plaintext[1:]
