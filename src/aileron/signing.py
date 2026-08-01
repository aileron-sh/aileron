"""Aileron ed25519 checkpoint signing for hash-chained logs."""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import chainlog
from .events import canonical_json

PRIVATE_KEY_NAME = "aileron_ed25519.key"
PUBLIC_KEY_NAME = "aileron_ed25519.pub"


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _canonical(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def _signed_payload(checkpoint: dict) -> bytes:
    """Bytes that were signed: canonical JSON of the checkpoint minus
    signature/pubkey_path."""
    return _canonical(
        {k: v for k, v in checkpoint.items() if k not in ("signature", "pubkey_path")}
    )


def generate_keypair(dir_path: str) -> tuple[str, str]:
    """Generate an ed25519 keypair in ``dir_path``.

    Writes ``aileron_ed25519.key`` (unencrypted PKCS8 PEM private key) and
    ``aileron_ed25519.pub`` (SubjectPublicKeyInfo PEM). Returns
    ``(private_key_path, public_key_path)``.
    """
    Path(dir_path).mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    key_path = os.path.join(str(dir_path), PRIVATE_KEY_NAME)
    pub_path = os.path.join(str(dir_path), PUBLIC_KEY_NAME)
    # Create the private key 0o600 from the start (never a world-readable
    # window before a follow-up chmod) and refuse to follow a pre-planted
    # symlink at the target path. O_TRUNC (not O_EXCL) keeps `aileron init`
    # idempotent: re-running regenerates the key in place.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(key_path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)  # normalize perms if the file pre-existed
    with open(pub_path, "wb") as fh:
        fh.write(
            private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key_path, pub_path


def sign_checkpoint(log_path: str, key_path: str) -> dict:
    """Sign the current tip of the log at ``log_path`` with the key at ``key_path``.

    Verifies the chain first (raises ValueError if broken), then appends a
    JSON line ``{ts, log_path, count, tip_hash, signature, pubkey_path}`` to
    ``<log_path>.checkpoints.jsonl`` and returns the checkpoint dict.
    ``signature`` is base64 ed25519 over the canonical JSON of
    ``{ts, log_path, count, tip_hash}``.
    """
    result = chainlog.verify(log_path)
    if not result.ok:
        raise ValueError(f"refusing to sign broken chain: {result.errors}")
    events = chainlog.ChainLog.read(log_path)
    tip_hash = events[-1]["hash"] if events else chainlog.GENESIS_PREV_HASH

    with open(key_path, "rb") as fh:
        private = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"not an ed25519 private key: {key_path}")

    pub_path = os.path.join(os.path.dirname(key_path) or ".", PUBLIC_KEY_NAME)
    checkpoint = {
        "ts": _now_ts(),
        "log_path": str(log_path),
        "count": result.count,
        "tip_hash": tip_hash,
    }
    signature = private.sign(_canonical(checkpoint))
    checkpoint["signature"] = base64.b64encode(signature).decode("ascii")
    checkpoint["pubkey_path"] = pub_path

    ckpt_file = f"{log_path}.checkpoints.jsonl"
    with open(ckpt_file, "a", encoding="utf-8") as fh:
        fh.write(canonical_json(checkpoint) + "\n")
    return checkpoint


def _load_public_key(key_path: str) -> Ed25519PublicKey:
    """Load an ed25519 public key from ``key_path``; accepts a PEM public key,
    a PEM private key (public half derived), or a directory containing the
    standard keypair files (the public key is preferred, so verification
    hosts never need the private key present)."""
    path = key_path
    if os.path.isdir(path):
        path = os.path.join(path, PUBLIC_KEY_NAME)
        if not os.path.exists(path):
            path = os.path.join(key_path, PRIVATE_KEY_NAME)
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        key = serialization.load_pem_private_key(data, password=None).public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"not an ed25519 key: {key_path}")
    return key


def verify_checkpoint(log_path: str, key_path: str) -> bool:
    """Verify the latest checkpoint for ``log_path`` against ``key_path``.

    Checkpoints cover a *prefix* of an append-only log: the chain must be
    intact, the log must still contain at least ``count`` events, the event
    at position ``count`` must hash to the checkpoint's ``tip_hash``, and the
    ed25519 signature must be valid. Events legitimately appended after the
    checkpoint was signed do not invalidate it; truncation below the
    checkpointed prefix, or any rewrite of it, does.
    """
    ckpt_file = f"{log_path}.checkpoints.jsonl"
    if not os.path.exists(ckpt_file):
        return False
    checkpoints = []
    with open(ckpt_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                checkpoints.append(json.loads(line))
    if not checkpoints:
        return False
    checkpoint = checkpoints[-1]

    count = checkpoint.get("count")
    if not isinstance(count, int) or count < 0:
        return False
    result = chainlog.verify(log_path)
    if not result.ok or result.count < count:
        return False
    events = chainlog.ChainLog.read(log_path)
    prefix_tip = events[count - 1]["hash"] if count else chainlog.GENESIS_PREV_HASH
    if prefix_tip != checkpoint.get("tip_hash"):
        return False

    try:
        public = _load_public_key(key_path)
        signature = base64.b64decode(checkpoint["signature"])
        public.verify(signature, _signed_payload(checkpoint))
    except Exception:
        return False
    return True
