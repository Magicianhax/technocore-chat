/**
 * Re-verify the published conformance vectors from a second language.
 *
 * This is NOT a client and reimplements no protocol rule — no sweep, no canonical-string
 * assembly. It reads `vectors.json`, derives each Ed25519 public key from its `did:key`
 * (multibase base58btc + the fixed `ed25519-pub` multicodec), and checks that every `sig`
 * verifies against its already-canonical string. If it does, the vectors are real Ed25519
 * signatures that any language's crypto agrees on — which is the whole claim a client in
 * another language relies on when it diffs its own output against this file.
 *
 *     node tests/conformance/verify.mjs
 *
 * Exit 0 = every signature verifies. Node stdlib only; test_conformance.py shells out to
 * this when a `node` binary is present and skips it otherwise (CI is pure-Python).
 */

import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX = Object.fromEntries([...B58].map((c, i) => [c, i]));

function b58decode(str) {
  let n = 0n;
  for (const ch of str) {
    const d = B58_INDEX[ch];
    if (d === undefined) throw new Error(`bad base58btc char ${JSON.stringify(ch)}`);
    n = n * 58n + BigInt(d);
  }
  const body = [];
  while (n > 0n) {
    body.unshift(Number(n % 256n));
    n /= 256n;
  }
  let zeros = 0;
  for (const ch of str) {
    if (ch === '1') zeros++;
    else break;
  }
  return Buffer.from([...Array(zeros).fill(0), ...body]);
}

// The 32 raw public-key bytes wrapped in the fixed DER SPKI prefix for Ed25519, so
// node:crypto will build a verify key from them.
function verifyKey(did) {
  const mb = did.slice('did:key:'.length);
  const decoded = b58decode(mb.slice(1)); // drop the multibase 'z'
  const raw = decoded.subarray(2); // drop the 0xed 0x01 multicodec
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

const v = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));
const key = verifyKey(v.did);

let fail = 0;
const check = (name, canonical, sig) => {
  const ok = verify(null, Buffer.from(canonical, 'utf8'), key, Buffer.from(sig, 'base64url'));
  if (!ok) {
    fail++;
    console.error(`FAIL ${name}: signature does not verify`);
  }
};

for (const m of v.messages) check(`message nonce=${m.nonce}`, m.canonical, m.sig);
check('note', v.note.canonical, v.note.sig);

if (fail === 0) console.log(`ok: ${v.messages.length + 1} signatures verify from Node`);
process.exit(fail === 0 ? 0 : 1);
