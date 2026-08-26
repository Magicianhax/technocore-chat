"""Regenerate `vectors.json` from the authoritative signer and sweep.

The vectors are a *published artifact*, not a hand-authored fixture: every field here comes
from `store.clean_text` and an Ed25519 signature over the canonical string, from a fixed seed
key so the output is byte-stable. A client in any language diffs its own output against this
file; a stack that reimplemented the sweep or the canonical string from prose sees a mismatch
instead of a silent 403 on the first zero-width space (the failure mode issue #75 is about).

    uv run python tests/conformance/generate.py     # rewrites vectors.json

`test_conformance.py` asserts the committed file equals a fresh run of this, so a change to
the sweep, the canonical string, or the signature encoding fails CI until the vectors are
regenerated — the vectors cannot drift away from the rules they claim to pin.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import didkey
import store

# One byte, repeated 32×: a reproducible Ed25519 seed. Any language can rebuild the same key
# from `seed_byte`, which is why it travels in the file.
SEED_BYTE = 7

# Chosen to exercise exactly the traps the #75 thread found independently across clients:
# per-character (not run-collapsing) sweep, Python str.strip() at the edges, every swept
# category, NBSP surviving the sweep but dying in the trim, and astral / non-ASCII text.
MESSAGE_TEXTS = [
    "hello world",
    "a  b",  # two spaces: the sweep is 1:1, never a run-collapse
    "a\tb",  # Cc (tab) -> space
    "a​b",  # Cf (zero-width space)
    "a‍b",  # Cf (ZWJ)
    "a‮b",  # Cf (bidi RLO)
    "ab",  # Co (private use)
    "a b",  # Zl (line separator)
    "a b",  # Zp (paragraph separator)
    "  trim me  ",  # ASCII edge whitespace, trimmed
    " nbsp edges ",  # Zs at the edges: survives the sweep, dies in the trim
    "a b",  # Zs interior: survives
    "\U0001d173note",  # astral Cf at the start
    "Ünïcödé and \U0001f680",  # non-ASCII kept
    "url/significant?and=chars#x",  # path/query punctuation, carried in the URL
]

NOTE = {"ns": store.OWNERS_NS, "key": "d-demo", "nonce": 5}


def _multibase(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = didkey._B58[rem] + out
    return out


def build() -> dict:
    key = Ed25519PrivateKey.from_private_bytes(bytes([SEED_BYTE]) * 32)
    raw = key.public_key().public_bytes_raw()
    did = didkey.PREFIX + "z" + _multibase(didkey.MULTICODEC_ED25519 + raw)

    def sign(canonical: str) -> str:
        return base64.urlsafe_b64encode(key.sign(canonical.encode("utf-8"))).decode().rstrip("=")

    messages = []
    for i, text in enumerate(MESSAGE_TEXTS):
        swept = store.clean_text(text)
        canonical = f"lobby|{i + 1}|{swept}"
        messages.append(
            {
                "text": text,
                "swept": swept,
                "room": "lobby",
                "nonce": i + 1,
                "canonical": canonical,
                "sig": sign(canonical),
            }
        )

    note_swept = store.clean_text(did, store.MAX_VALUE_CHARS)
    note_canonical = f"{NOTE['ns']}|{NOTE['key']}|{NOTE['nonce']}|{note_swept}"
    note = dict(
        NOTE, value=did, swept=note_swept, canonical=note_canonical, sig=sign(note_canonical)
    )

    fp = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return {
        "seed_byte": SEED_BYTE,
        "did": did,
        "fingerprint": fp,
        "note_path": f"/kv/did-{fp[:2]}/{fp[2:]}",
        "messages": messages,
        "note": note,
    }


VECTORS_PATH = Path(__file__).with_name("vectors.json")


def render(data: dict) -> str:
    # ensure_ascii=False so the swept forms are readable in the file; a trailing newline so
    # the committed artifact is diff-clean.
    return json.dumps(data, ensure_ascii=False, indent=1) + "\n"


if __name__ == "__main__":
    VECTORS_PATH.write_text(render(build()), encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(Path.cwd())}")
