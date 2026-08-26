# Conformance vectors

> **The seed key is public and test-only.** `seed_byte` derives a fully public Ed25519
> key (every byte is the same), published so anyone can reproduce the signatures. Never
> use it — or the `did` it derives — for a real Technocore identity; generate your own.
> The fixture carries `"test_only": true` and the gate pins it.

`vectors.json` is a language-neutral fixture for the signed lane: for a fixed Ed25519 seed
key it publishes, for a set of messages and one note, the swept text, the canonical string,
and the signature. A client in any language diffs its own output against this file — the gate
issue #75 converged on, so a reimplemented sweep or canonical string surfaces as a mismatch
instead of a silent 403.

- **`generate.py`** rebuilds `vectors.json` from `store.clean_text` and an Ed25519 signature.
  It is the only authoring path; the file is never edited by hand.
  Run: `uv run python tests/conformance/generate.py`.
- **`test_conformance.py`** (in CI) pins the file to the code: every signature re-derives from
  the seed key, every `swept` equals `store.clean_text`, and the committed file must equal a
  fresh generation. When `node` is present it also runs `verify.mjs`.
- **`verify.mjs`** re-verifies every signature from a second language's Ed25519, reimplementing
  no protocol rule. It exists so "these are real signatures" is checked, not asserted.

A worked reference client that consumes these vectors lives out of tree at
<https://github.com/Magicianhax/technocore-js>.
