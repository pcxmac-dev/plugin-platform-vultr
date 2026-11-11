"""The account's SSH keys (the reference: a key added "for use with future instances. This does not update any running
instances"): a public key checked before it is sent, its fingerprint as `ssh-keygen -l` gives it (SHA256, base64 without
padding). A private key is never taken."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct

TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
         "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-dss")
MAX_KEY = 16 * 1024
NAME_MAX = 255


def blob_of(key: str) -> tuple[str, bytes, str]:
    """A public key's type, its decoded blob and its comment; ValueError when it is none."""
    text = " ".join(str(key or "").split())
    if "PRIVATE KEY" in text.upper():
        raise ValueError("that is a private key: give the public one (the .pub file), never the private")
    if not text:
        raise ValueError("no key given")
    if len(text) > MAX_KEY:
        raise ValueError(f"a public key is at most {MAX_KEY // 1024} KB")
    parts = text.split(" ", 2)
    if len(parts) < 2 or parts[0] not in TYPES:
        raise ValueError(f"not an OpenSSH public key: it begins with its type ({', '.join(TYPES[:3])} ...) and its base64")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        (n,) = struct.unpack(">I", blob[:4])
        inner = blob[4:4 + n].decode("ascii")
    except (binascii.Error, ValueError, struct.error, UnicodeDecodeError):
        raise ValueError("not an OpenSSH public key: its base64 part does not read") from None
    if inner != parts[0]:
        raise ValueError(f"not an OpenSSH public key: its base64 holds a {inner or 'no'} key, not {parts[0]}")
    return parts[0], blob, parts[2] if len(parts) > 2 else ""


def checked(name: str, key: str) -> tuple[str, str]:
    """A key's name and the key as sent (one line: its type, its base64, its comment); ValueError when either is none."""
    n = " ".join(str(name or "").split())
    if not n:
        raise ValueError("the key needs a name")
    if len(n) > NAME_MAX or re.search(r"[\x00-\x1f\x7f]", n):
        raise ValueError(f"a key's name is one line of at most {NAME_MAX} characters")
    kind, blob, comment = blob_of(key)
    return n, " ".join(x for x in (kind, base64.b64encode(blob).decode("ascii"), comment) if x)


def fingerprint(key: str) -> str:
    """The key's SHA256 fingerprint as ssh-keygen shows it ("" when it is no public key)."""
    try:
        _, blob, _ = blob_of(key)
    except ValueError:
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def same_key(a: str, b: str) -> bool:
    """Whether two public keys are the same key (their type and blob; the comments aside)."""
    try:
        return blob_of(a)[:2] == blob_of(b)[:2]
    except ValueError:
        return False


def kind_of(key: str) -> str:
    parts = str(key or "").split()
    return parts[0] if parts else ""
