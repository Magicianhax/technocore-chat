"""The conformance vectors are a published contract — test them like one.

`vectors.json` exists so a client in any language can diff its own output against one
authoritative source instead of a hand-copied `INVISIBLE_CATEGORIES` that nothing checks
(issue #75, and the ~9% silent fingerprint-miss rate measured in the wild). These tests pin
the file to the code it claims to reproduce, so it can never quietly drift:

  - every signature re-derives from the same seed key and canonical string;
  - every `swept` field equals `store.clean_text` of its raw text;
  - the committed file equals a fresh `generate.py` run — a sweep or encoding change fails
    here until the vectors are regenerated;
  - and, when a `node` binary is present, an independent Ed25519 stack re-verifies every
    signature (`verify.mjs`), so "these are real signatures, not this repo marking its own
    homework" is checked rather than asserted. CI is pure-Python and simply skips that one.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import didkey
import store
from conformance import generate

HERE = Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))


def _seed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([VECTORS["seed_byte"]]) * 32)


def test_every_signature_reproduces_from_the_signer():
    """The authoritative gate: sign each canonical string with the seed key and compare to
    the published `sig`. Ed25519 is deterministic, so any drift in the canonical string or
    the signature encoding changes these 86 characters."""
    key = _seed_key()
    for m in VECTORS["messages"]:
        want = base64.urlsafe_b64encode(key.sign(m["canonical"].encode())).decode().rstrip("=")
        assert want == m["sig"], f"message nonce={m['nonce']}"
    note = VECTORS["note"]
    want = base64.urlsafe_b64encode(key.sign(note["canonical"].encode())).decode().rstrip("=")
    assert want == note["sig"]


def test_each_sig_verifies_and_is_canonically_encoded():
    """The signatures verify against the DID in the file, and each is the canonical spelling
    the signed lane accepts after #177 (last character in AQgw)."""
    for m in VECTORS["messages"]:
        didkey.verify(VECTORS["did"], m["sig"], m["canonical"])
        assert m["sig"][-1] in "AQgw", f"non-canonical sig, nonce={m['nonce']}"
    didkey.verify(VECTORS["did"], VECTORS["note"]["sig"], VECTORS["note"]["canonical"])


def test_swept_fields_match_clean_text():
    """Every `swept` is exactly what the server stores, so a client comparing against it is
    comparing against the real sweep — including the traps: 1:1 (not run-collapsed) spaces,
    NBSP surviving interior but trimmed at the edges."""
    for m in VECTORS["messages"]:
        assert store.clean_text(m["text"]) == m["swept"], repr(m["text"])
    note = VECTORS["note"]
    assert store.clean_text(note["value"], store.MAX_VALUE_CHARS) == note["swept"]


def test_canonical_strings_are_well_formed():
    """`room|nonce|swept` and `ns|key|nonce|swept` — the free-form field is last, so the
    canonical string parses one way only (app.py `_signer`)."""
    for m in VECTORS["messages"]:
        assert m["canonical"] == f"{m['room']}|{m['nonce']}|{m['swept']}"
    note = VECTORS["note"]
    assert note["canonical"] == f"{note['ns']}|{note['key']}|{note['nonce']}|{note['swept']}"


def test_identity_fields_match():
    key = _seed_key()
    raw = key.public_key().public_bytes_raw()
    assert didkey.public_key(VECTORS["did"]) == raw
    fp = VECTORS["fingerprint"]
    assert VECTORS["note_path"] == f"/kv/did-{fp[:2]}/{fp[2:]}"


def test_the_seed_key_is_marked_public_and_test_only():
    """The seed is a publicly-known key by construction (every byte is SEED_BYTE), so the
    fixture must say so machine-readably — a client author copying `seed_byte` into a real
    identity is the one way this file can cause harm."""
    assert VECTORS["test_only"] is True
    assert "warning" in VECTORS


def test_committed_vectors_are_in_sync_with_the_generator():
    """The file on disk equals a fresh generation, so it cannot drift away from the rules it
    pins. Regenerate with `uv run python tests/conformance/generate.py`."""
    fresh = generate.render(generate.build())
    on_disk = (HERE / "vectors.json").read_text(encoding="utf-8")
    assert fresh == on_disk, "vectors.json is stale — run tests/conformance/generate.py"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed (CI is pure-Python)")
def test_node_reverifies_the_vectors():
    """A second language agrees the signatures are real. verify.mjs reimplements no protocol
    rule — it only checks Ed25519 signatures against the already-canonical strings."""
    out = subprocess.run(
        ["node", str(HERE / "verify.mjs")], capture_output=True, text=True, cwd=HERE.parents[1]
    )
    assert out.returncode == 0, out.stdout + out.stderr
